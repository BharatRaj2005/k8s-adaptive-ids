"""Load a trained model and classify CICFlowMeter flows."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from src.detection.models import decide, predict_proba
from src.preprocessing.schema import (
    DST_IP,
    DST_PORT,
    FLOW_ID,
    LABEL,
    PROTOCOL,
    SRC_IP,
    SRC_PORT,
    TIMESTAMP,
    SchemaError,
    align_features,
    parse_timestamps,
    read_flow_csv,
)
from src.utils.config import get_path, load_config
from src.utils.native import ensure_libgomp

PREDICTION_COLUMNS = [
    "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "predicted_label", "predicted_class", "confidence", "is_malicious",
    "capture_file", "source", "processing_time_ms", "detected_at", "true_label", "model",
]
VALID_SOURCES = ("dataset", "pcap", "live", "unknown")


def _column(df: pd.DataFrame, name: str, dtype: str) -> pd.Series:
    if name not in df.columns:
        return pd.Series(pd.NA, index=df.index, dtype=dtype)
    if dtype == "Int64":
        return pd.to_numeric(df[name], errors="coerce").round().astype("Int64")
    s = df[name].astype("string").str.strip()
    return s.mask(s == "", pd.NA)


class FlowPredictor:
    def __init__(self, model_dir: str | Path):
        self.model_dir = Path(model_dir)
        if not (self.model_dir / "model.joblib").is_file():
            raise FileNotFoundError(f"no trained model in {self.model_dir}; run python -m src.detection.train")
        ensure_libgomp()  # LightGBM models need OpenMP to unpickle
        self.preprocessor = joblib.load(self.model_dir / "preprocessor.joblib")
        self.model = joblib.load(self.model_dir / "model.joblib")
        self.schema = json.loads((self.model_dir / "feature_schema.json").read_text())
        class_map = json.loads((self.model_dir / "class_mapping.json").read_text())
        self.features: list[str] = self.schema["input_features"]
        self.benign_label: int = class_map["benign_label"]
        self.class_names = {int(k): v for k, v in class_map["all_classes"].items()}
        self.classes = np.asarray(self.model.classes_)
        # Validation-tuned attack threshold (models trained with --tune-threshold);
        # older models have no decision.json and use plain argmax.
        decision_file = self.model_dir / "decision.json"
        decision = json.loads(decision_file.read_text()) if decision_file.is_file() else {}
        self.attack_threshold: float | None = decision.get("attack_threshold")
        self.name = self.model_dir.name
        self.last_report: dict[str, Any] = {}

    @classmethod
    def from_config(cls, name: str | None = None, cfg: dict[str, Any] | None = None) -> "FlowPredictor":
        cfg = cfg or load_config()
        return cls(get_path("models_dir", cfg) / (name or cfg["detection"]["active_model"]))

    def predict_frame(self, df: pd.DataFrame, capture_file: str | None = None, source: str = "unknown") -> pd.DataFrame:
        if source not in VALID_SOURCES:
            raise ValueError(f"source must be one of {VALID_SOURCES}")
        if df.empty:
            self.last_report = {"rows": 0, "missing_features": [], "batch_ms": 0.0}
            return pd.DataFrame(columns=PREDICTION_COLUMNS)
        X, missing = align_features(df, self.features)
        if len(missing) / len(self.features) > self.schema["max_missing_feature_fraction"]:
            raise SchemaError(f"{len(missing)}/{len(self.features)} model features missing: {missing[:10]}")

        t0 = time.perf_counter()
        proba = predict_proba(self.model, self.preprocessor.transform(X))
        batch_ms = (time.perf_counter() - t0) * 1000
        labels, confidence = decide(proba, self.classes, self.benign_label, self.attack_threshold)

        ts = parse_timestamps(df[TIMESTAMP]) if TIMESTAMP in df.columns else pd.Series(pd.NaT, index=df.index)
        out = pd.DataFrame({
            "flow_id": _column(df, FLOW_ID, "string"),
            "timestamp": ts.dt.strftime("%Y-%m-%dT%H:%M:%S.%f").astype("string"),
            "src_ip": _column(df, SRC_IP, "string"),
            "src_port": _column(df, SRC_PORT, "Int64"),
            "dst_ip": _column(df, DST_IP, "string"),
            "dst_port": _column(df, DST_PORT, "Int64"),
            "protocol": _column(df, PROTOCOL, "Int64"),
            "predicted_label": labels,
            "predicted_class": [self.class_names.get(int(c), str(c)) for c in labels],
            "confidence": confidence.round(6),
            "is_malicious": labels != self.benign_label,
            "capture_file": capture_file,
            "source": source,
            "processing_time_ms": batch_ms / len(df),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "true_label": _column(df, LABEL, "Int64"),
            "model": self.name,
        }, index=df.index)
        self.last_report = {"rows": int(len(df)), "missing_features": missing, "batch_ms": batch_ms}
        return out.reset_index(drop=True)

    def predict_csv(self, path: str | Path, source: str = "unknown") -> pd.DataFrame:
        path = Path(path)
        return self.predict_frame(read_flow_csv(path), capture_file=path.name, source=source)


def to_records(pred: pd.DataFrame) -> list[dict[str, Any]]:
    """JSON-friendly records: pandas NA/NaN become None (never invented values)."""
    records = pred.astype(object).where(pred.notna(), None).to_dict(orient="records")
    for r in records:
        for k, v in r.items():
            if isinstance(v, np.generic):
                r[k] = v.item()
    return records
