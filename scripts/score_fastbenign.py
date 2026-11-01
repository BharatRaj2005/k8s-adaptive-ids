"""Offline fast-benign validation: score the captured benign flows with each model.

Reads the independent fast-benign lab sets (data/lab/fbenign_*) and their sidecar
(fastbenign_meta.json). For each model it reports, over the benign flows and over the
generator pod's flows specifically: benign false-positive rate (with denominators),
the predicted attack classes of the false positives, and the confidence distribution.
It also computes the model-independent behavioural flow-burst alerts and whether the
MAPE-K controller would activate deception. Nothing is written to training; no model
or backend state is changed.
"""
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from src.detection.behavior import flow_bursts
from src.detection.predictor import FlowPredictor
from src.preprocessing.dataset import CAPTURE_FILE
from src.preprocessing.lab_data import load_lab_set
from src.preprocessing.schema import DST_IP, LABEL, SRC_IP
from src.utils import db
from src.utils.config import load_config

CFG = load_config()
BENIGN = CFG["benign_label"]
MODELS = ["et_dataset_sqrt_lab", "v2_et_none"]
META = json.load(open("data/lab/fastbenign_meta.json"))
OUT = Path("reports/fastbenign_validation.md")

# window duration per capture csv (for behavioural rate)
with db.connect(db.db_path(CFG)) as c:
    WIN = {Path(r[0]).name: (r[1] or 10.0) for r in
           c.execute("SELECT csv_file, duration_s FROM captures WHERE csv_file IS NOT NULL").fetchall()}


def conf_hist(conf):
    bins = [0, 0.3, 0.5, 0.7, 0.9, 1.01]
    names = ["<0.3", "0.3-0.5", "0.5-0.7", "0.7-0.9", ">=0.9"]
    idx = np.digitize(conf, bins) - 1
    return {names[i]: int((idx == i).sum()) for i in range(len(names))}


def predict(model, df):
    fp = FlowPredictor.from_config(model)
    out = fp.predict_frame(df.reset_index(drop=True), source="live")
    return fp, out


def score_model(model, sets):
    # aggregate per model over all sets; also keep per-set generator-pod view
    all_gen = []          # generator-pod benign flows (prediction rows)
    all_ben = []          # all benign flows
    behave = []           # behavioural bursts from the generator
    per_set = []
    for name, meta in sets.items():
        lab = load_lab_set(name, drop_ambiguous=True).reset_index(drop=True)
        _, pred = predict(model, lab)
        pred = pred.reset_index(drop=True)
        lab = lab.reset_index(drop=True)
        pod = meta["pod_ip"]
        is_ben = (lab[LABEL].to_numpy() == BENIGN)
        gen_mask = ((lab[SRC_IP] == pod) | (lab[DST_IP] == pod)).to_numpy() & is_ben
        ben = pred[is_ben].copy()
        gen = pred[gen_mask].copy()
        all_ben.append(ben)
        all_gen.append(gen)
        # behavioural bursts per capture window, generator source only
        bw = 0
        lab_cap = lab[CAPTURE_FILE] if CAPTURE_FILE in lab.columns else pd.Series(["w"] * len(lab))
        for cap, idx in lab.groupby(lab_cap).groups.items():
            win = WIN.get(Path(str(cap)).name, 10.0)
            b = flow_bursts(pred.loc[idx], win, CFG)
            bw += int((b["src_ip"] == pod).sum()) if not b.empty else 0
        behave.append(bw)
        fp_gen = int(gen["is_malicious"].sum())
        per_set.append({
            "set": name, "scenario": meta["scenario"], "target": meta["target"],
            "gen_flows": int(len(gen)), "gen_fp": fp_gen,
            "gen_fpr": round(fp_gen / len(gen), 4) if len(gen) else None,
            "gen_fp_classes": dict(Counter(gen[gen["is_malicious"]]["predicted_class"])),
            "behaviour_bursts": bw,
        })
    gen = pd.concat(all_gen) if all_gen else pd.DataFrame()
    ben = pd.concat(all_ben) if all_ben else pd.DataFrame()
    gfp = gen[gen["is_malicious"]] if len(gen) else gen
    summary = {
        "model": model,
        "benign_flows_all": int(len(ben)), "fp_all": int(ben["is_malicious"].sum()) if len(ben) else 0,
        "gen_benign_flows": int(len(gen)), "gen_fp": int(len(gfp)),
        "gen_fpr": round(len(gfp) / len(gen), 4) if len(gen) else None,
        "gen_fpr_conf_ge_0.9": round(int((gfp["confidence"] >= 0.9).sum()) / len(gen), 4) if len(gen) else None,
        "fp_classes": dict(Counter(gfp["predicted_class"])) if len(gfp) else {},
        "gen_conf_hist": conf_hist(gen["confidence"].to_numpy()) if len(gen) else {},
        "fp_conf_hist": conf_hist(gfp["confidence"].to_numpy()) if len(gfp) else {},
        "behaviour_bursts_total": int(sum(behave)),
        "per_set": per_set,
    }
    return summary


def main():
    sets = {k: v for k, v in META.items() if (Path("data/lab") / k).is_dir()}
    results = {m: score_model(m, sets) for m in MODELS}
    print(json.dumps({m: {k: v for k, v in r.items() if k != "per_set"} for m, r in results.items()}, indent=2))
    Path("reports").mkdir(exist_ok=True)
    OUT.write_text(render(results, sets), encoding="utf-8")
    print("\nwrote", OUT)


def render(results, sets):
    L = ["# Fast-benign validation (offline scoring)", "",
         "Fresh benign capture, independent of training. Flows scored offline with each model via the",
         "production `FlowPredictor` path (threshold + unknown gate). Ground truth: all generated traffic",
         "is benign, so any attack verdict is a false positive. 'Generator flows' are the scenario pod's",
         "flows (the fast-benign traffic of interest); the rest of each window is cluster background.", ""]
    L.append("## Capture")
    L.append("| Set | Scenario | Target | Generator benign flows |")
    L.append("|---|---|---|--:|")
    for name, m in sets.items():
        gf = results[MODELS[0]]["per_set"]
        row = next((r for r in gf if r["set"] == name), {})
        L.append(f"| {name} | {m['scenario']} | {m['target']} | {row.get('gen_flows', '?')} |")
    L.append("")
    L.append("## Benign false positives on generator (fast-benign) flows")
    L.append("| Model | Gen flows (denom) | FP | FPR | FPR conf>=0.9 | FP classes | Behaviour bursts |")
    L.append("|---|--:|--:|--:|--:|---|--:|")
    for m in MODELS:
        r = results[m]
        L.append(f"| {m} | {r['gen_benign_flows']} | {r['gen_fp']} | {r['gen_fpr']} | "
                 f"{r['gen_fpr_conf_ge_0.9']} | {r['fp_classes'] or '-'} | {r['behaviour_bursts_total']} |")
    L.append("")
    for m in MODELS:
        r = results[m]
        L.append(f"### {m}")
        L.append(f"- Confidence histogram over generator benign flows: {r['gen_conf_hist']}")
        L.append(f"- Confidence histogram over the false positives: {r['fp_conf_hist'] or '-'}")
        L.append(f"- All benign flows (incl. background): {r['fp_all']} FP / {r['benign_flows_all']}")
        L.append("")
        L.append("| Set | Scenario | Gen flows | FP | FPR | FP classes | Bursts |")
        L.append("|---|---|--:|--:|--:|---|--:|")
        for s in r["per_set"]:
            L.append(f"| {s['set']} | {s['scenario']} | {s['gen_flows']} | {s['gen_fp']} | {s['gen_fpr']} | "
                     f"{s['gen_fp_classes'] or '-'} | {s['behaviour_bursts']} |")
        L.append("")
    L.append("## MAPE-K deception (would it activate on this benign traffic?)")
    L.append("Deception deploys on an attack verdict: an ML-malicious flow from an eligible source, or a")
    L.append("behavioural flow-burst. Behavioural bursts are model-independent (flow rate only).")
    for m in MODELS:
        r = results[m]
        ml = r["gen_fp"] > 0
        bh = r["behaviour_bursts_total"] > 0
        L.append(f"- **{m}**: ML false deception trigger: {'YES' if ml else 'no'} ({r['gen_fp']} FP flows); "
                 f"behavioural trigger: {'YES' if bh else 'no'} ({r['behaviour_bursts_total']} bursts) -> "
                 f"would deploy decoys: **{'YES' if (ml or bh) else 'no'}**")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
