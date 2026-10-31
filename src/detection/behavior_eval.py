"""Replay recorded capture windows through the behavioural detectors and the ML classifier.

    python -m src.detection.behavior_eval   # sessions from config behavior_eval.sessions and
                                            # data/lab/behavior_sessions/*.json (scripts/behaviour_scenarios.py)

Ground truth comes from the lab: each session lists the pod IPs of the traffic
generator Jobs that acted as attackers, with the time span they ran. A (window,
source) pair is an *attack pair* when an attacker pod sent TCP flows in that
window, and a *benign pair* for every other source with TCP flows in it.
Windows are replayed in time order with a fresh adaptive state, so the learned
thresholds only use windows that precede the one being scored.

Detectors scored on the same pairs:
  fixed     the unchanged flow-burst rule (behavior.py)
  adaptive  fixed rule + learned thresholds (adaptive_behavior.py)
  ml        >= `behavior_eval.ml_min_flows` flows of the source classified as an
            attack by the active per-flow model (flow-level ML, aggregated per source)
  hybrid    adaptive OR ml
  policy    the MAPE-K controller's decision rules on the same evidence (would it act?):
            fixed-rule burst; or ML with one flow at >= high confidence, or >= repeat_count
            flows at >= medium confidence in the repeat window, or a medium-confidence
            flow corroborated by a behavioural alert; or a learned-threshold alert with
            a >= medium-confidence ML flow of the same source in the repeat window
The flow-level ML result (share of attacker / benign flows classified as an
attack) is reported separately from the pair-level detectors.

Sessions carry a role: `calibration` sessions were used while developing the
detector; `evaluation` sessions were recorded afterwards and never used to set
any parameter.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd

from src.detection.adaptive_behavior import AdaptiveBehavior
from src.detection.behavior import flow_bursts
from src.detection.evaluate import wilson_interval
from src.preprocessing.schema import DST_IP, DST_PORT, PROTOCOL, SRC_IP, read_flow_csv
from src.utils import db
from src.utils.config import get_path, load_config

DETECTORS = ("fixed", "adaptive", "ml", "hybrid", "policy")


def _ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def load_windows(start: str, end: str, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute(
            "SELECT csv_file, started_at, ended_at, duration_s FROM captures WHERE status = 'classified' "
            "AND csv_file IS NOT NULL AND started_at >= ? AND started_at < ? ORDER BY started_at", (start, end))]
    out, flows_dir = [], get_path("flows_dir", cfg)
    for r in rows:
        path = flows_dir / r["csv_file"]
        if not path.is_file():
            continue
        f = read_flow_csv(path)
        pred = pd.DataFrame({"src_ip": f[SRC_IP], "dst_ip": f[DST_IP], "dst_port": f[DST_PORT],
                             "protocol": f[PROTOCOL], "is_malicious": False, "predicted_class": "n/a"})
        out.append({**r, "start": _ts(r["started_at"]), "end": _ts(r["ended_at"]), "pred": pred, "flows": f})
    return out


def dataset_windows(prefix: str, cfg: dict[str, Any], window_s: float, offset: float = 0.0,
                    max_seconds: float | None = None) -> list[dict[str, Any]]:
    """Fixed-length windows of a dataset capture, cut by flow start time and shifted by `offset` s."""
    from src.preprocessing.dataset import CAPTURE, TS, capture_prefix, load_dataset

    df = load_dataset(cfg)
    df = df[df[CAPTURE].map(capture_prefix) == prefix].sort_values(TS)
    t = df[TS].map(lambda x: x.timestamp()).to_numpy()
    t0 = t.min()
    if max_seconds:
        df, t = df[t - t0 < max_seconds], t[t - t0 < max_seconds]
    out = []
    for k, g in df.groupby(((t - t0) // window_s).astype(int)):
        start = t0 + k * window_s + offset
        pred = pd.DataFrame({"src_ip": g[SRC_IP], "dst_ip": g[DST_IP], "dst_port": g[DST_PORT],
                             "protocol": g[PROTOCOL], "is_malicious": False, "predicted_class": "n/a"})
        out.append({"csv_file": prefix, "duration_s": window_s, "start": start, "end": start + window_s,
                    "pred": pred.reset_index(drop=True)})
    return out


def _rate(n: int, d: int) -> dict[str, Any]:
    return {"n": int(n), "of": int(d), "rate": n / d if d else None, "ci95": wilson_interval(int(n), int(d))}


def ml_per_window(windows: list[dict[str, Any]], predictor) -> list[pd.DataFrame]:
    out = []
    for w in windows:
        p = predictor.predict_frame(w["flows"], source="pcap")
        out.append(p[["src_ip", "dst_port", "protocol", "is_malicious", "predicted_class", "confidence"]])
    return out


def score(session: dict[str, Any], windows: list[dict[str, Any]], cfg: dict[str, Any], predictor,
          skip: int = 0) -> dict[str, Any]:
    attackers = {s["ip"]: s for s in session["scenarios"]}
    protos = cfg["behavior"]["protocols"]
    ml_min = cfg["behavior_eval"]["ml_min_flows"]
    preds = ml_per_window(windows, predictor) if predictor is not None else [None] * len(windows)

    # flagged sources per window for every detector, plus per-window cost of the behavioural ones
    adaptive = AdaptiveBehavior(cfg)
    flagged: dict[str, list[set]] = {d: [] for d in DETECTORS}
    alerts_n: dict[str, list[int]] = {d: [] for d in DETECTORS}
    cost_ms: dict[str, list[float]] = {"fixed": [], "adaptive": []}
    types: dict[str, int] = {}
    th = cfg["deception"]["thresholds"]
    ml_hist: list[tuple[float, str, float]] = []      # (window end, source, confidence) of ML attack flows
    beh_hist: list[tuple[float, str]] = []
    for w, p in zip(windows, preds):
        t = time.perf_counter()
        fx = flow_bursts(w["pred"], w["duration_s"], cfg)
        cost_ms["fixed"].append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        ad = adaptive.analyze(w["pred"], w["duration_s"], w["end"])
        cost_ms["adaptive"].append((time.perf_counter() - t) * 1000)
        for k in ad["alert_type"]:
            types[k] = types.get(k, 0) + 1
        ml = set()
        if p is not None:
            m = p[p["is_malicious"].astype(bool) & p["protocol"].isin(protos)]
            counts = m.groupby("src_ip").size()
            ml = set(counts[counts >= ml_min].index)
        for d, s, n in (("fixed", set(fx["src_ip"]), len(fx)), ("adaptive", set(ad["src_ip"]), len(ad)),
                        ("ml", ml, len(ml))):
            flagged[d].append(s)
            alerts_n[d].append(n)
        flagged["hybrid"].append(flagged["adaptive"][-1] | ml)
        alerts_n["hybrid"].append(len(flagged["hybrid"][-1]))
        # controller policy, evaluated on evidence up to this window
        since = w["end"] - th["repeat_window_seconds"]
        if p is not None:
            m = p[p["is_malicious"].astype(bool)]
            ml_hist += [(w["end"], sv, float(cf)) for sv, cf in zip(m["src_ip"], m["confidence"])]
        beh_hist += [(w["end"], sv) for sv in ad["src_ip"]]
        ml_hist = [x for x in ml_hist if x[0] > since]
        beh_hist = [x for x in beh_hist if x[0] > since]
        act = set(fx["src_ip"])
        recent_beh = {sv for _, sv in beh_hist}
        for src in {sv for _, sv, _ in ml_hist}:
            confs = [cf for _, sv, cf in ml_hist if sv == src]
            med = [cf for cf in confs if cf >= th["medium_confidence"]]
            if max(confs) >= th["high_confidence"] or len(med) >= th["repeat_count"] or (med and src in recent_beh):
                act.add(src)
        medium = set(ad.loc[ad["severity"] == "medium", "src_ip"])
        for src in medium:
            if any(sv == src and cf >= th["medium_confidence"] for _, sv, cf in ml_hist):
                act.add(src)
        flagged["policy"].append(act)
        alerts_n["policy"].append(len(act))

    # the first `skip` windows only warm up the adaptive state
    windows, preds = windows[skip:], preds[skip:]
    for d in DETECTORS:
        flagged[d], alerts_n[d] = flagged[d][skip:], alerts_n[d][skip:]
    for d in cost_ms:
        cost_ms[d] = cost_ms[d][skip:]
    res: dict[str, Any] = {}
    for d in DETECTORS:
        if d in ("ml", "hybrid", "policy") and predictor is None:
            continue
        tp = fp = fn = tn = 0
        first: dict[str, float] = {}
        det_w = {ip: 0 for ip in attackers}
        act_w = {ip: 0 for ip in attackers}
        false_src: dict[str, int] = {}
        for w, fl in zip(windows, flagged[d]):
            sources = set(w["pred"].loc[w["pred"]["protocol"].isin(protos), "src_ip"].dropna())
            for src in sources:
                attack, hit = src in attackers, src in fl
                if attack:
                    act_w[src] += 1
                    det_w[src] += hit
                    if hit and src not in first:
                        first[src] = w["end"]
                tp += attack and hit
                fn += attack and not hit
                fp += (not attack) and hit
                tn += (not attack) and not hit
                if hit and not attack:
                    false_src[src] = false_src.get(src, 0) + 1
        scen = {}
        for ip, s in attackers.items():
            # scenario start: first request in the generator log, else the start of the first window
            # with flows from the attacker (then the delay is overestimated by < 1 window)
            seen = [w["start"] for w in windows if (w["pred"]["src_ip"] == ip).any()]
            start = _ts(s["start"]) if s.get("start") else (min(seen) if seen else float("nan"))
            scen[s["name"]] = {"ip": ip, "group": s.get("group", s["name"]), "kind": s.get("kind", "recon"),
                               "rate_per_s": s.get("rate_per_s"), "requests": s.get("requests"),
                               "windows": _rate(det_w[ip], act_w[ip]),
                               "detected": ip in first,
                               "delay_s": round(first[ip] - start, 1) if ip in first else None}
        res[d] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                  "detection_rate": _rate(tp, tp + fn), "false_positive_rate": _rate(fp, fp + tn),
                  "precision": _rate(tp, tp + fp),
                  "alerts_per_window_mean": float(np.mean(alerts_n[d])) if alerts_n[d] else 0.0,
                  "alerts_per_window_max": int(max(alerts_n[d], default=0)),
                  "false_alert_sources": false_src, "scenarios": scen}
        if d in cost_ms:
            res[d]["cpu_ms_per_window"] = {"median": float(np.median(cost_ms[d])),
                                           "p95": float(np.percentile(cost_ms[d], 95))}
    res["adaptive"]["alert_types"] = types
    res["adaptive"]["state_bytes"] = len(json.dumps(adaptive.state))

    flow_level = None
    if predictor is not None:
        flow_level = {"model": predictor.name, "scenarios": {}, "benign": None}
        b_mal = b_all = 0
        for p in preds:
            tcp = p[p["protocol"].isin(protos)]
            ben = tcp[~tcp["src_ip"].isin(attackers)]
            b_all += len(ben)
            b_mal += int(ben["is_malicious"].sum())
        flow_level["benign"] = _rate(b_mal, b_all)
        for ip, s in attackers.items():
            fl = pd.concat([p[(p["src_ip"] == ip) & p["protocol"].isin(protos)] for p in preds])
            flow_level["scenarios"][s["name"]] = {
                "flows_flagged": _rate(int(fl["is_malicious"].sum()), len(fl)),
                "as_recon": _rate(int((fl["predicted_class"] == "Node-RED Reconnaissance").sum()), len(fl)),
                "confidence_median": float(fl["confidence"].median()) if len(fl) else None}
    return {"name": session["name"], "role": session.get("role", "evaluation"), "windows": len(windows),
            "from": session["from"], "to": session["to"], "results": res, "flow_level_ml": flow_level}


def main() -> None:
    from src.detection.predictor import FlowPredictor

    cfg = load_config()
    predictor = FlowPredictor.from_config(cfg=cfg)
    out = {"generated_at": datetime.now().astimezone().isoformat(), "config": cfg["behavior"],
           "eval_config": cfg["behavior_eval"], "model": predictor.name, "sessions": []}
    recorded = sorted((get_path("processed_dir", cfg).parent / "lab" / "behavior_sessions").glob("*.json"))
    sessions = [*cfg["behavior_eval"]["sessions"], *(json.loads(p.read_text()) for p in recorded)]
    for s in sessions:
        windows = load_windows(s["from"], s["to"], cfg)
        out["sessions"].append(score(s, windows, cfg, predictor))
    for ds in cfg["behavior_eval"].get("dataset_sessions", []):
        w = ds.get("window_s", 10.0)
        windows = []
        if ds.get("warmup"):
            windows = dataset_windows(ds["warmup"]["capture"], cfg, w, max_seconds=ds["warmup"]["seconds"])
        offset = (windows[-1]["end"] if windows else 0.0)
        main_w = dataset_windows(ds["capture"], cfg, w)
        shift = offset - main_w[0]["start"] + w if windows else 0.0
        for x in main_w:
            x["start"] += shift
            x["end"] += shift
        session = {"name": ds["name"], "role": ds.get("role", "evaluation"), "from": ds["capture"], "to": ds["capture"],
                   "scenarios": ds.get("attackers", [])}
        # ML not scored: the model was trained on these captures. Warm-up windows feed the
        # adaptive state but are not scored.
        res = score(session, windows + main_w, cfg, None, skip=len(windows))
        res["warmup_windows"], res["windows"] = len(windows), len(main_w)
        out["sessions"].append(res)
    for s in out["sessions"]:
        for det, r in s["results"].items():
            print(f"{s['name']:10s} {det:9s} DR={r['detection_rate']['n']}/{r['detection_rate']['of']} "
                  f"FP={r['false_positive_rate']['n']}/{r['false_positive_rate']['of']} "
                  f"prec={r['precision']['rate']} false={r['false_alert_sources']}")
    path = get_path("reports_dir", cfg) / "behavioural_detection.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    print("wrote", path)


if __name__ == "__main__":
    main()
