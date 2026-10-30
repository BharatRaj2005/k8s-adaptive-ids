"""Score trained models on flows captured from the lab, using lab ground truth.

Ground truth comes from the controlled traffic generator: flows between the
attacker pod and the attacked service port are the attack; any other flow of the
attacker pod (e.g. its DNS lookups) is excluded as ambiguous; every remaining
flow is treated as benign because nothing else attacks the isolated lab.

    python -m src.detection.live_eval --attacker-ip 10.42.0.181 --attack-label 2 --target-port 1880
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.detection.predictor import FlowPredictor
from src.preprocessing.schema import DST_IP, DST_PORT, SRC_IP, SRC_PORT, read_flow_csv
from src.utils.config import class_names, get_path, load_config

THRESHOLDS = (0.5, 0.7, 0.9)


def ground_truth(df: pd.DataFrame, attacker_ips: set[str], target_port: int | None) -> pd.Series:
    """'attack', 'benign' or 'ambiguous' per flow."""
    involves = df[SRC_IP].isin(attacker_ips) | df[DST_IP].isin(attacker_ips)
    on_port = (df[DST_PORT] == target_port) | (df[SRC_PORT] == target_port) if target_port else True
    gt = pd.Series("benign", index=df.index)
    gt[involves] = "ambiguous"
    gt[involves & on_port] = "attack"
    return gt


def load_flows(csvs: list[Path]) -> pd.DataFrame:
    frames = [read_flow_csv(p).assign(_csv=p.name) for p in csvs]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def evaluate_model(predictor: FlowPredictor, flows: pd.DataFrame, gt: pd.Series, attack_label: int) -> dict[str, Any]:
    pred = predictor.predict_frame(flows.drop(columns=["_csv"]), source="pcap")
    benign, attack = gt.to_numpy() == "benign", gt.to_numpy() == "attack"
    mal = pred["is_malicious"].to_numpy()
    conf = pred["confidence"].to_numpy()
    correct = pred["predicted_label"].to_numpy() == attack_label
    out: dict[str, Any] = {
        "model": predictor.name,
        "attack_label_in_model": attack_label in set(int(c) for c in predictor.classes),
        "benign_flows": int(benign.sum()),
        "attack_flows": int(attack.sum()),
        "benign_fpr": float(mal[benign].mean()) if benign.any() else None,
        "attack_detected_any_class": float(mal[attack].mean()) if attack.any() else None,
        "attack_detected_correct_class": float(correct[attack].mean()) if attack.any() else None,
        "benign_fp_classes": pred.loc[benign & mal, "predicted_class"].value_counts().to_dict(),
        "attack_predicted_classes": pred.loc[attack, "predicted_class"].value_counts().to_dict(),
    }
    for th in THRESHOLDS:
        out[f"benign_fpr_conf_ge_{th}"] = float((mal & (conf >= th))[benign].mean()) if benign.any() else None
        out[f"attack_correct_conf_ge_{th}"] = float((correct & (conf >= th))[attack].mean()) if attack.any() else None
    return out


def evaluate_lab_sets(set_names: list[str], model_names: list[str] | None = None,
                      cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Score models on recorded lab sets (ground truth from each set's manifest)."""
    from src.preprocessing.lab_data import load_lab_set, load_manifest
    from src.preprocessing.schema import LABEL

    cfg = cfg or load_config()
    models_dir = get_path("models_dir", cfg)
    names = model_names or sorted(p.parent.name for p in models_dir.glob("*/model.joblib"))
    predictors = [FlowPredictor(models_dir / n) for n in names]
    report: dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "sets": {}}
    for s in set_names:
        m = load_manifest(s, cfg)
        flows = load_lab_set(s, cfg, drop_ambiguous=False)
        gt = flows[LABEL].map(lambda v: "ambiguous" if pd.isna(v) else ("benign" if v == cfg["benign_label"] else "attack"))
        flows = flows.drop(columns=[c for c in flows.columns if c.startswith("_")]).assign(_csv=None)
        report["sets"][s] = {
            "manifest": {k: v for k, v in m.items() if k != "files"},
            "ground_truth_counts": gt.value_counts().to_dict(),
            "results": [evaluate_model(p, flows, gt, m["attack_label"] if m["kind"] == "attack" else -1)
                        for p in predictors],
        }
    return report


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lab-set", action="append", help="evaluate recorded lab sets instead of raw CSVs")
    ap.add_argument("--attacker-ip", action="append")
    ap.add_argument("--attack-label", type=int)
    ap.add_argument("--target-port", type=int)
    ap.add_argument("--csv", type=Path, action="append", help="flow CSVs (default: all in captures/flows)")
    ap.add_argument("--models", nargs="*", help="model names (default: all trained 11-class and attack_focused models)")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    cfg = load_config()
    if args.lab_set:
        report = evaluate_lab_sets(args.lab_set, args.models, cfg)
        out = args.out or get_path("reports_dir", cfg) / "lab_validation.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, default=str))
        f = lambda v: "  -  " if v is None else f"{v:.3f}"
        for s, rep in report["sets"].items():
            print(f"\n== {s} {rep['ground_truth_counts']}")
            print(f"{'model':32s} {'benignFPR':>9s} {'FPR@0.9':>8s} {'atk any':>8s} {'atk class':>9s} {'class@0.9':>9s}")
            for r in rep["results"]:
                print(f"{r['model']:32s} {f(r['benign_fpr']):>9s} {f(r['benign_fpr_conf_ge_0.9']):>8s} "
                      f"{f(r['attack_detected_any_class']):>8s} {f(r['attack_detected_correct_class']):>9s} "
                      f"{f(r['attack_correct_conf_ge_0.9']):>9s}")
        print("saved", out)
        return
    if not args.attacker_ip or args.attack_label is None:
        ap.error("--attacker-ip and --attack-label are required unless --lab-set is used")
    csvs = args.csv or sorted(get_path("flows_dir", cfg).glob("*.csv"))
    flows = load_flows(csvs)
    if flows.empty:
        raise SystemExit("no flows found")
    gt = ground_truth(flows, set(args.attacker_ip), args.target_port)
    models_dir = get_path("models_dir", cfg)
    names = args.models or sorted(p.parent.name for p in models_dir.glob("*/model.joblib"))
    results = [evaluate_model(FlowPredictor(models_dir / n), flows, gt, args.attack_label) for n in names]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "csv_files": [p.name for p in csvs],
        "flows": int(len(flows)),
        "ground_truth_counts": gt.value_counts().to_dict(),
        "attacker_ips": args.attacker_ip,
        "attack_label": args.attack_label,
        "attack_class": class_names(cfg)[args.attack_label],
        "target_port": args.target_port,
        "results": results,
    }
    out = args.out or get_path("reports_dir", cfg) / "live_validation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"flows={report['flows']} ground truth={report['ground_truth_counts']}")
    print(f"{'model':30s} {'benignFPR':>9s} {'FPR@0.9':>8s} {'atk any':>8s} {'atk class':>9s} {'class@0.9':>9s}")
    for r in results:
        f = lambda v: "n/a" if v is None else f"{v:.3f}"
        print(f"{r['model']:30s} {f(r['benign_fpr']):>9s} {f(r['benign_fpr_conf_ge_0.9']):>8s} "
              f"{f(r['attack_detected_any_class']):>8s} {f(r['attack_detected_correct_class']):>9s} "
              f"{f(r['attack_correct_conf_ge_0.9']):>9s}")
    print("saved", out)


if __name__ == "__main__":
    main()
