"""Per-class precision / recall / F1 of one or more models over the held-out lab sets.

The dataset test split measures the published captures; this measures the lab traffic the live system
sees. All held-out lab sets are pooled (attacker flows carry the set's class, everything else is benign),
scored with the model as in live operation (unknown-traffic gate on), and reported per class, so
cross-class confusion (e.g. SSRF vs traversal on Grafana) lowers precision. Read-only.
Usage: lab_class_report.py <model> [<model> ...]
"""
import sys

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

from src.detection.predictor import FlowPredictor
from src.preprocessing.lab_data import load_lab_set
from src.preprocessing.schema import LABEL
from src.utils.config import load_config

CFG = load_config()
NAMES = {int(k): v for k, v in CFG["classes"].items()}

EVAL_SETS = [
    "benign_eval_a", "benign_eval_b",
    "fbenign_api_nodered", "fbenign_api_grafana", "fbenign_api_influxdb", "fbenign_burst_nodered",
    "fbenign_browse_grafana", "fbenign_keepalive_grafana", "fbenign_poller_influxdb", "fbenign_poller_nodered",
    "recon_run2", "recon_threaded_nodered", "recon_slow_nodered", "recon_slow_influx", "recon_seq_grafana",
    "recon_seq_influx", "recon_shuffled_grafana",
    "attack_nodered_rce_eval", "attack_nodered_rce_eval_r1",
    "attack_grafana_traversal_eval", "attack_grafana_traversal_eval_r1",
    "attack_influx_authbypass_eval", "attack_influx_authbypass_eval_r1",
    "attack_grafana_ssrf_eval",
]


def pooled():
    frames = []
    for name in EVAL_SETS:
        try:
            df = load_lab_set(name, drop_ambiguous=True)
        except FileNotFoundError:
            continue
        frames.append(df.assign(lab_set=name))
    return pd.concat(frames, ignore_index=True)


def report(model, lab):
    fp = FlowPredictor.from_config(model)
    pred = fp.predict_frame(lab, source="live").reset_index(drop=True)
    y = lab[LABEL].astype(int).map(NAMES)
    # unknown / benign-predicted flows count as Benign (they never reach an attack class)
    p = pred["predicted_class"].where(pred["is_malicious"], NAMES[CFG["benign_label"]])
    classes = [NAMES[c] for c in sorted(set(lab[LABEL].astype(int)))]
    pr, rc, f1, n = precision_recall_fscore_support(y, p, labels=classes, zero_division=0)
    out = pd.DataFrame({"class": classes, "precision": pr, "recall": rc, "f1": f1, "support": n})
    per_set = (pd.DataFrame({"set": lab["lab_set"], "y": y, "p": p})
               .query("y != @NAMES[0]").assign(hit=lambda d: d.y == d.p).groupby("set")["hit"].mean())
    return out, per_set


if __name__ == "__main__":
    lab = pooled()
    print("pooled held-out lab flows: %d from %d sets" % (len(lab), lab["lab_set"].nunique()))
    for model in sys.argv[1:]:
        out, per_set = report(model, lab)
        print("\n=== %s" % model)
        print(out.to_string(index=False, float_format=lambda v: "%.3f" % v))
        print("correct-class recall per attack/recon set:")
        print(per_set.to_string(float_format=lambda v: "%.3f" % v))
