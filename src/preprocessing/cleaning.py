"""Data-quality checks and label-noise analysis."""
from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.dataset import CAPTURE
from src.preprocessing.schema import DST_PORT, LABEL, PROTOCOL, SRC_PORT


def data_quality_report(df: pd.DataFrame, features: list[str]) -> dict[str, Any]:
    num = df[features].apply(pd.to_numeric, errors="coerce")
    values = num.to_numpy(dtype=float)
    nan_counts = num.isna().sum()
    inf_counts = pd.Series(np.isinf(values).sum(axis=0), index=features)
    neg_counts = (num < 0).sum()
    nunique = num.nunique(dropna=False)
    dup_feat_label = int(df.duplicated(subset=features + [LABEL]).sum())
    dedup = df.drop_duplicates(subset=features + [LABEL])
    labels_per_vector = dedup.groupby(features, dropna=False)[LABEL].nunique()
    return {
        "rows": int(len(df)),
        "features": len(features),
        "class_counts": {int(k): int(v) for k, v in df[LABEL].value_counts().sort_index().items()},
        "nan_by_column": {c: int(v) for c, v in nan_counts.items() if v},
        "inf_by_column": {c: int(v) for c, v in inf_counts.items() if v},
        "negative_by_column": {c: int(v) for c, v in neg_counts.items() if v},
        "constant_columns": [c for c, v in nunique.items() if v <= 1],
        "exact_duplicate_rows": int(df.duplicated().sum()),
        "duplicate_feature_label_rows": dup_feat_label,
        "feature_vectors_with_conflicting_labels": int((labels_per_vector > 1).sum()),
        "duplicate_rate_by_capture": {
            cap: round(float(g.duplicated(subset=features).mean()), 4) for cap, g in df.groupby(CAPTURE)
        },
    }


def _service_keys(df: pd.DataFrame, port_col: str) -> pd.Series:
    return df[PROTOCOL].astype("Int64").astype(str) + ":" + df[port_col].astype("Int64").astype(str)


def background_service_signatures(background: pd.DataFrame, min_count: int) -> set[str]:
    """(protocol:port) pairs that recur in pure background traffic.

    Flow direction in CICFlowMeter can be either way round, so both ports are
    counted. Only ports below 32768 are considered so ephemeral client ports are ignored.
    """
    counts: Counter[str] = Counter()
    for col in (DST_PORT, SRC_PORT):
        keys = _service_keys(background, col)[background[col] < 32768]
        counts.update(keys.tolist())
    return {k for k, v in counts.items() if v >= min_count}


def background_like_mask(df: pd.DataFrame, signatures: set[str]) -> pd.Series:
    return _service_keys(df, DST_PORT).isin(signatures) | _service_keys(df, SRC_PORT).isin(signatures)


def label_noise_analysis(df: pd.DataFrame, signatures: set[str], benign_label: int) -> dict[str, Any]:
    """Fraction of flows per attack class that look like ordinary cluster background."""
    mask = background_like_mask(df, signatures)
    per_class = {}
    for label, g in df.groupby(LABEL):
        m = mask.loc[g.index]
        per_class[int(label)] = {
            "flows": int(len(g)),
            "background_like": int(m.sum()),
            "background_like_fraction": round(float(m.mean()), 4),
            "remaining_flows": int((~m).sum()),
        }
    return {
        "signatures": sorted(signatures),
        "per_class": per_class,
        "note": (
            "Attack captures are whole-node captures labelled per capture; flows matching "
            "infrastructure service signatures learned from the benign background capture "
            "are most likely unrelated to the attack itself."
        ),
        "benign_label": benign_label,
    }
