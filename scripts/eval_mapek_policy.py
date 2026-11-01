"""Evaluate MAPE-K deception policies offline, using the real controller decision functions.

For each lab set it scores the generator/attacker pod's flows with the active model, derives the
ML evidence (high/medium-confidence malicious counts) and the behavioural flow-burst, then asks the
actual controller whether a decoy would deploy for that source. Benign sets must yield no decoy;
scanner/attack sets should. Reports false decoy activations vs attack detection and sweeps a few
ML-corroboration policies. Read-only: no model, backend or decoy state is changed.
Usage: eval_mapek_policy.py [model_name]   (default: the configured active model)
"""
import json
import sys
from pathlib import Path

import pandas as pd

from src.detection.behavior import flow_bursts
from src.deception.controller import MapeKController, behaviour_actionable
from src.detection.predictor import FlowPredictor
from src.preprocessing.dataset import CAPTURE_FILE
from src.preprocessing.lab_data import load_lab_set
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, PROTOCOL, SRC_IP
from src.utils import db
from src.utils.config import load_config

CFG = load_config()
BENIGN = CFG["benign_label"]
MODEL = sys.argv[1] if len(sys.argv) > 1 else CFG["detection"]["active_model"]

# ground-truth kind per lab set: benign sets must not deploy; scanner/attack should
BENIGN_SETS = ["fbenign_api_nodered", "fbenign_api_grafana", "fbenign_api_influxdb",
               "fbenign_burst_nodered", "fbenign_browse_grafana",
               "fbenign_keepalive_grafana", "fbenign_poller_influxdb",  # behaviour types in no training set
               "fbenign_poller_nodered"]  # poller on the app the slow-recon training set targets
SCANNER_SETS = ["recon_run1", "recon_run2", "recon_threaded_nodered", "recon_slow_nodered", "recon_seq_grafana",
                "recon_seq_influx", "recon_shuffled_grafana", "recon_slow_influx"]
ATTACK_SETS = ["attack_nodered_rce_eval", "attack_grafana_traversal_eval", "attack_influx_authbypass_eval",
               "attack_nodered_rce_eval_r1", "attack_grafana_traversal_eval_r1", "attack_influx_authbypass_eval_r1",
               "attack_grafana_ssrf_eval"]

with db.connect(db.db_path(CFG)) as c:
    WIN = {Path(r[0]).name: (r[1] or 10.0) for r in
           c.execute("SELECT csv_file, duration_s FROM captures WHERE csv_file IS NOT NULL").fetchall()}

META = json.load(open("data/lab/fastbenign_meta.json")) if Path("data/lab/fastbenign_meta.json").is_file() else {}


def pod_ip_for(name):
    if name in META:
        return META[name]["pod_ip"]
    m = Path("data/lab") / name / "manifest.json"
    if m.is_file():
        ips = json.loads(m.read_text()).get("attacker_ips") or []
        return ips[0] if ips else None
    return None


def evidence_for_set(name, fp):
    """Return per-attacker-source ML/behaviour evidence computed with the active model."""
    lab = load_lab_set(name, drop_ambiguous=True).reset_index(drop=True)
    pred = fp.predict_frame(lab, source="live").reset_index(drop=True)
    pod = pod_ip_for(name)
    if pod is None:
        return None
    gen = ((lab[SRC_IP] == pod) | (lab[DST_IP] == pod)).to_numpy()
    p = pred[gen].copy()
    mal = p[p["is_malicious"]]
    # burst from this source in any window
    burst = False
    cap = lab[CAPTURE_FILE] if CAPTURE_FILE in lab.columns else pd.Series(["w"] * len(lab))
    for capfile, idx in lab.groupby(cap).groups.items():
        b = flow_bursts(pred.loc[idx], WIN.get(Path(str(capfile)).name, 10.0), CFG)
        if not b.empty and (b["src_ip"] == pod).any():
            burst = True
    # dominant malicious class + its count/conf (ML path groups by src, class)
    cls_counts = mal["predicted_class"].value_counts()
    top_cls = cls_counts.index[0] if len(cls_counts) else None
    top = mal[mal["predicted_class"] == top_cls] if top_cls else mal
    th = CFG["deception"]["thresholds"]
    return {
        "set": name, "pod": pod, "gen_flows": int(gen.sum()), "mal": int(len(mal)),
        "ml_high": int((mal["confidence"] >= th["high_confidence"]).sum()),
        "ml_med": int((mal["confidence"] >= th["medium_confidence"]).sum()),
        "top_class": top_cls, "top_count": int(len(top)),
        "top_conf": float(top["confidence"].max()) if len(top) else 0.0,
        "burst": burst,
        "all_mal_conf": mal["confidence"].tolist(),
        "top_mal_conf": top["confidence"].tolist() if len(top) else [],
    }


def sweep(rows, ctrl, high, med, repeat):
    """Re-evaluate the deploy decision for every set under a candidate policy (offline)."""
    th = {"high_confidence": high, "medium_confidence": med, "repeat_count": repeat,
          "repeat_window_seconds": 300}
    out = []
    for ev in rows:
        ml_high = sum(1 for c in ev["all_mal_conf"] if c >= high)
        ml_med = sum(1 for c in ev["all_mal_conf"] if c >= med)
        top_n_med = sum(1 for c in ev["top_mal_conf"] if c >= med)
        ml_act = False
        if ev["top_class"] and ev["top_class"] in ctrl.d["attack_policy"]:
            conf = ev["top_conf"]
            ml_act = conf >= high or (conf >= med and (top_n_med >= repeat or ev["burst"]))
        bh_act = ev["burst"] and (ml_high > 0 or ml_med >= repeat)
        out.append({**ev, "deploy": ml_act or bh_act})
    df = pd.DataFrame(out)
    return (int(((df.kind == "benign") & df.deploy).sum()), int(((df.kind == "scanner") & df.deploy).sum()),
            int(((df.kind == "attack") & df.deploy).sum()))


def would_deploy(ev, ctrl, th):
    """Faithful decision: ML path (_assess) OR behaviour path (behaviour_actionable)."""
    reasons = []
    ml_act = False
    if ev["top_class"] and ev["top_class"] != ctrl.benign_class and ev["top_class"] in ctrl.d["attack_policy"]:
        a = ctrl._assess("ml", ev["pod"], ev["top_class"], ev["top_conf"], ev["top_count"], ev["burst"], {}, False)
        ml_act = a["actionable"]
        if ml_act:
            reasons.append("ML: " + a["reason"])
    bh_act = False
    if ev["burst"]:
        assessment, bh_act, why = behaviour_actionable(True, ev["ml_high"], ev["ml_med"], 1, th)
        if bh_act:
            reasons.append("behaviour: " + why)
    return (ml_act or bh_act), reasons


def main():
    fp = FlowPredictor.from_config(MODEL)
    ctrl = MapeKController(CFG)
    th = CFG["deception"]["thresholds"]
    rows = []
    for name in BENIGN_SETS + SCANNER_SETS + ATTACK_SETS:
        if not (Path("data/lab") / name).is_dir():
            continue
        kind = "benign" if name in BENIGN_SETS else "scanner" if name in SCANNER_SETS else "attack"
        ev = evidence_for_set(name, fp)
        if ev is None:
            print("skip", name, "(no pod ip)")
            continue
        deploy, reasons = would_deploy(ev, ctrl, th)
        ev.update(kind=kind, deploy=deploy, reason="; ".join(reasons))
        rows.append(ev)
        print("%-28s %-7s gen=%4d mal=%4d ml>=0.9=%3d ml>=0.6=%3d burst=%s top=%s(%d@%.2f) -> DEPLOY=%s"
              % (name, kind, ev["gen_flows"], ev["mal"], ev["ml_high"], ev["ml_med"], ev["burst"],
                 ev["top_class"], ev["top_count"], ev["top_conf"], deploy))
    df = pd.DataFrame(rows)
    false_act = int(((df.kind == "benign") & df.deploy).sum())
    recon_det = int(((df.kind == "scanner") & df.deploy).sum())
    atk_det = int(((df.kind == "attack") & df.deploy).sum())
    print("\n=== model: %s" % MODEL)
    print("=== policy: behavior_requires_ml=%s high=%.2f med=%.2f repeat=%d ==="
          % (th.get("behavior_requires_ml"), th["high_confidence"], th["medium_confidence"], th["repeat_count"]))
    print("false decoy activations (benign): %d / %d" % (false_act, int((df.kind == "benign").sum())))
    print("scanner sets triggering a decoy:  %d / %d" % (recon_det, int((df.kind == "scanner").sum())))
    print("attack sets triggering a decoy:   %d / %d" % (atk_det, int((df.kind == "attack").sum())))
    print("\n=== policy sweep (benign false / scanner detected / attack detected) ===")
    print("%-40s %8s %8s %8s" % ("policy", "false", "scanner", "attack"))
    for high, med, rep in [(0.9, 0.6, 3), (0.9, 0.7, 3), (0.9, 0.7, 5), (0.9, 0.8, 3)]:
        fa, sc, at = sweep(rows, ctrl, high, med, rep)
        print("%-40s %4d/%-3d %4d/%-3d %4d/%-3d"
              % ("high>=%.2f med>=%.2f repeat=%d" % (high, med, rep), fa, int((df.kind == "benign").sum()),
                 sc, int((df.kind == "scanner").sum()), at, int((df.kind == "attack").sum())))
    out = "reports/mapek_policy_eval.json" if MODEL == CFG["detection"]["active_model"] else f"reports/mapek_policy_eval_{MODEL}.json"
    df.drop(columns=["all_mal_conf", "top_mal_conf"]).to_json(out, orient="records", indent=2)
    print("wrote", out)
    return df


if __name__ == "__main__":
    main()
