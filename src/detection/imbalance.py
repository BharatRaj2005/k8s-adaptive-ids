"""Class-imbalance strategies, applied to the (already split, preprocessed) training matrix only.

  none         - no weighting
  balanced     - sample weight n / (k * n_c), the usual "balanced" class weight
  sqrt         - sample weight (n_max / n_c) ** 0.5, a softer cost-sensitive weighting
  undersample  - keep at most `benign_ratio` benign rows per attack row (balanced sampling)
  smote        - synthetic minority rows by interpolating between same-class nearest
                 neighbours (SMOTE, Chawla et al. 2002) up to `smote_target` rows per class

Resampling happens after the train/test split and after preprocessing is fitted, on
training rows only, so no synthetic or duplicated row can reach validation or test data.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors

STRATEGIES = ("none", "balanced", "sqrt", "undersample", "smote")


def class_weights(y: np.ndarray, strategy: str) -> dict[int, float]:
    labels, counts = np.unique(y, return_counts=True)
    if strategy == "balanced":
        w = len(y) / (len(labels) * counts)
    elif strategy == "sqrt":
        w = np.sqrt(counts.max() / counts)
    else:
        w = np.ones_like(counts, dtype=float)
    return {int(lab): float(v) for lab, v in zip(labels, w)}


def smote(X: np.ndarray, y: np.ndarray, target: int, k: int, rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray]:
    """Oversample every class below `target` rows; classes with < 2 rows are left unchanged."""
    new_X, new_y = [X], [y]
    for lab in np.unique(y):
        Xc = X[y == lab]
        need = target - len(Xc)
        if need <= 0 or len(Xc) < 2:
            continue
        # neighbours in a log-scaled space: CICFlowMeter features span many orders of magnitude
        Z = np.sign(Xc) * np.log1p(np.abs(Xc))
        nn = NearestNeighbors(n_neighbors=min(k, len(Xc) - 1) + 1).fit(Z)
        neigh = nn.kneighbors(Z, return_distance=False)[:, 1:]
        base = rng.integers(0, len(Xc), size=need)
        mate = neigh[base, rng.integers(0, neigh.shape[1], size=need)]
        gap = rng.random((need, 1))
        new_X.append(Xc[base] + gap * (Xc[mate] - Xc[base]))
        new_y.append(np.full(need, lab, dtype=y.dtype))
    return np.vstack(new_X), np.concatenate(new_y)


def undersample(X: np.ndarray, y: np.ndarray, benign_label: int, ratio: float,
                rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray]:
    benign_idx = np.flatnonzero(y == benign_label)
    attack = int((y != benign_label).sum())
    keep_n = min(len(benign_idx), max(1, int(round(ratio * attack))))
    keep = np.concatenate([np.flatnonzero(y != benign_label), rng.choice(benign_idx, keep_n, replace=False)])
    keep.sort()
    return X[keep], y[keep]


def apply(X: pd.DataFrame, y: np.ndarray, spec: dict[str, Any], benign_label: int,
          random_state: int) -> tuple[pd.DataFrame, np.ndarray, np.ndarray | None, dict[str, Any]]:
    """Return (X, y, sample_weight, report) for a strategy spec {'strategy': ..., ...}."""
    strategy = spec.get("strategy", "none")
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown imbalance strategy {strategy!r}, expected one of {STRATEGIES}")
    rng = np.random.default_rng(random_state)
    cols = X.columns
    Xa = X.to_numpy(dtype=float)
    before = {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
    if strategy == "undersample":
        Xa, y = undersample(Xa, y, benign_label, float(spec.get("benign_ratio", 20)), rng)
    elif strategy == "smote":
        Xa, y = smote(Xa, y, int(spec.get("smote_target", 500)), int(spec.get("smote_k", 5)), rng)
    weight = None
    if strategy in ("balanced", "sqrt"):
        cw = class_weights(y, strategy)
        weight = np.array([cw[int(v)] for v in y])
    after = {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
    report = {"strategy": strategy, "rows_before": before, "rows_after": after,
              "class_weights": class_weights(y, strategy) if weight is not None else None}
    return pd.DataFrame(Xa, columns=cols), y, weight, report
