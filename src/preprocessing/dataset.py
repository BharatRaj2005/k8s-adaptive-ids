"""Loading the Kubernetes misuse-detection dataset (yigitsever/kubernetes-dataset)."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pandas as pd

from src.preprocessing.schema import LABEL, TIMESTAMP, parse_timestamps, read_flow_csv
from src.utils.config import get_path, load_config
from src.utils.logging_setup import get_logger

log = get_logger(__name__)

# Bookkeeping columns added on load. The leading underscore keeps them out of features.
CAPTURE = "_capture"
CAPTURE_FILE = "_capture_file"
TS = "_ts"


class DatasetValidationError(ValueError):
    pass


def capture_id(path: Path) -> str:
    """'grafana_20230320T1603.pcap_Flow.csv' -> 'grafana_20230320T1603'."""
    return path.name.split(".pcap")[0]


def capture_prefix(cap_id: str) -> str:
    """'grafana_20230320T1603' -> 'grafana'."""
    return cap_id.rsplit("_", 1)[0]


def discover_capture_files(cfg: dict[str, Any] | None = None) -> list[Path]:
    cfg = cfg or load_config()
    root = get_path("dataset_dir", cfg)
    files: list[Path] = []
    for pattern in cfg["dataset"]["capture_globs"]:
        files.extend(sorted(root.glob(pattern)))
    if not files:
        raise FileNotFoundError(
            f"No dataset CSVs under {root}. Clone https://github.com/yigitsever/kubernetes-dataset there."
        )
    return files


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_capture(path: Path, cfg: dict[str, Any]) -> pd.DataFrame:
    label_col = cfg["dataset"]["label_column"]
    df = read_flow_csv(path, cfg["features"].get("column_aliases"))
    if label_col not in df.columns:
        raise DatasetValidationError(f"{path.name}: no '{label_col}' column")
    labels = pd.to_numeric(df[label_col], errors="coerce")
    if labels.isna().any():
        raise DatasetValidationError(f"{path.name}: {int(labels.isna().sum())} non-numeric labels")
    df[LABEL] = labels.astype(int)

    cap = capture_id(path)
    expected = cfg["dataset"]["expected_capture_labels"].get(capture_prefix(cap))
    found = sorted(df[LABEL].unique().tolist())
    if expected is None:
        raise DatasetValidationError(f"{path.name}: prefix '{capture_prefix(cap)}' not in expected_capture_labels")
    if found != [expected]:
        raise DatasetValidationError(f"{path.name}: expected label {expected}, found {found}")

    df[CAPTURE] = cap
    df[CAPTURE_FILE] = path.name
    df[TS] = parse_timestamps(df[TIMESTAMP]) if TIMESTAMP in df.columns else pd.NaT
    return df


def load_dataset(cfg: dict[str, Any] | None = None) -> pd.DataFrame:
    """Load all per-capture files, validating the filename -> label mapping."""
    cfg = cfg or load_config()
    frames = []
    for path in discover_capture_files(cfg):
        frames.append(load_capture(path, cfg))
        log.info("loaded %s (%d flows, label %d)", path.name, len(frames[-1]), frames[-1][LABEL].iloc[0])
    columns = [list(f.columns) for f in frames]
    if any(c != columns[0] for c in columns):
        raise DatasetValidationError("dataset files do not share an identical column layout")
    return pd.concat(frames, ignore_index=True)


def dataset_manifest(cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """File names, sizes and hashes, recorded with each trained model."""
    return [
        {"file": str(p.relative_to(get_path("dataset_dir", cfg))), "bytes": p.stat().st_size, "sha256": file_sha256(p)}
        for p in discover_capture_files(cfg)
    ]
