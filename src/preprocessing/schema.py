"""Reading CICFlowMeter CSV files into a consistent schema.

Handles quirks observed in real files:
  * the GintsEngelen CICFlowMeter fork appends the header row again for every
    batch it writes, so a header line can appear in the middle of the data;
  * different builds of the tool emit slightly different column sets;
  * column names may carry stray whitespace.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

# Network metadata columns (used for prediction output, never as features).
FLOW_ID = "Flow ID"
SRC_IP = "Src IP"
SRC_PORT = "Src Port"
DST_IP = "Dst IP"
DST_PORT = "Dst Port"
PROTOCOL = "Protocol"
TIMESTAMP = "Timestamp"
LABEL = "Label"

TEXT_COLUMNS = {FLOW_ID, SRC_IP, DST_IP, TIMESTAMP, LABEL}


class SchemaError(ValueError):
    """Raised when a flow CSV cannot be mapped onto the expected schema."""


def normalize_column_name(name: str) -> str:
    return re.sub(r"\s+", " ", str(name)).strip()


def read_flow_csv(path: str | Path, aliases: dict[str, str] | None = None) -> pd.DataFrame:
    """Read a CICFlowMeter CSV. Numeric columns are coerced; bad cells become NaN."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    df = pd.read_csv(path, low_memory=False, skipinitialspace=True)
    if df.empty and len(df.columns) == 0:
        raise SchemaError(f"{path} has no header")
    df.columns = [normalize_column_name(c) for c in df.columns]
    if aliases:
        df = df.rename(columns={normalize_column_name(k): v for k, v in aliases.items()})
    empty_unnamed = [c for c in df.columns if c.startswith("Unnamed:") and df[c].isna().all()]
    df = df.drop(columns=empty_unnamed)
    if FLOW_ID not in df.columns and SRC_IP not in df.columns:
        raise SchemaError(f"{path} does not look like a CICFlowMeter flow file (no '{FLOW_ID}'/'{SRC_IP}' column)")

    # Drop repeated header rows written mid-file.
    first = df.columns[0]
    repeated = df[first].astype(str).str.strip() == first
    if repeated.any():
        df = df.loc[~repeated]

    for col in df.columns:
        if col not in TEXT_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df.reset_index(drop=True)


def parse_timestamps(series: pd.Series) -> pd.Series:
    """Parse CICFlowMeter timestamps (several formats exist across versions)."""
    return pd.to_datetime(series, format="mixed", errors="coerce", dayfirst=False)


def align_features(df: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, list[str]]:
    """Return df restricted to `features` (in order) plus the list of missing ones.

    Matching is exact first, then case-insensitive. Missing columns are added as
    NaN so the fitted imputer can fill them; callers decide whether too many are missing.
    """
    lower = {c.lower(): c for c in df.columns}
    out = {}
    missing = []
    for feat in features:
        if feat in df.columns:
            out[feat] = df[feat]
        elif feat.lower() in lower:
            out[feat] = df[lower[feat.lower()]]
        else:
            missing.append(feat)
            out[feat] = pd.Series(float("nan"), index=df.index)
    return pd.DataFrame(out, index=df.index), missing
