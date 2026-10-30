"""Classify the flows in a CICFlowMeter CSV file and save the predictions.

Examples:
    python -m src.detection.predict_csv data/raw/kubernetes-dataset/malicious/reconnaissance_20230319T1704.pcap_Flow.csv --source dataset
    python -m src.detection.predict_csv captures/flows/window_0001.pcap_Flow.csv --source pcap
"""
from __future__ import annotations

import argparse
from pathlib import Path

from src.detection.predictor import VALID_SOURCES, FlowPredictor
from src.utils.config import get_path, load_config


def default_output(csv_path: Path) -> Path:
    out_dir = get_path("processed_dir") / "predictions"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{csv_path.name.removesuffix('.csv')}.predictions.csv"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", type=Path)
    ap.add_argument("--model", help=f"model directory name (default: {load_config()['detection']['active_model']})")
    ap.add_argument("--source", choices=VALID_SOURCES, default="unknown")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--save-db", action="store_true", help="also store the detections in SQLite")
    args = ap.parse_args(argv)

    if args.csv.suffix.lower() != ".csv":
        ap.error("input must be a .csv file")
    predictor = FlowPredictor.from_config(args.model)
    pred = predictor.predict_csv(args.csv, source=args.source)
    out = args.out or default_output(args.csv)
    pred.to_csv(out, index=False)

    rep = predictor.last_report
    print(f"model={predictor.name} flows={rep['rows']} batch={rep['batch_ms']:.1f} ms "
          f"missing_features={len(rep['missing_features'])}")
    if rep["missing_features"]:
        print("  missing (imputed with training medians):", rep["missing_features"])
    print(pred["predicted_class"].value_counts().to_string())
    print(f"malicious={int(pred['is_malicious'].sum())} mean_confidence={pred['confidence'].mean():.3f}")
    known = pred["true_label"].notna()
    if known.any():
        acc = (pred.loc[known, "true_label"] == pred.loc[known, "predicted_label"]).mean()
        print(f"agreement with file labels: {acc:.4f} (not an evaluation if the file was used in training)")
    print("saved", out)
    if args.save_db:
        from src.utils import db

        with db.connect() as conn:
            print("stored", db.insert_detections(conn, pred), "detections in", db.db_path())


if __name__ == "__main__":
    main()
