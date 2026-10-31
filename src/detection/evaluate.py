"""Evaluation metrics and latency measurement."""
from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)


def wilson_interval(successes: int, n: int, z: float = 1.96) -> list[float] | None:
    """95 % Wilson score interval for a proportion; None when n == 0."""
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [float(max(0.0, centre - half)), float(min(1.0, centre + half))]


def classification_metrics(y_true, y_pred, labels: list[int], names: dict[int, str], benign_label: int) -> dict[str, Any]:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    out: dict[str, Any] = {"accuracy": float(accuracy_score(y_true, y_pred)), "test_rows": int(len(y_true))}
    for avg in ("macro", "weighted"):
        p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, average=avg, zero_division=0)
        out[f"precision_{avg}"] = float(p)
        out[f"recall_{avg}"] = float(r)
        out[f"f1_{avg}"] = float(f)

    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, average=None, zero_division=0)
    out["per_class"] = [
        {"label": int(lab), "name": names.get(int(lab), str(lab)), "precision": float(p[i]),
         "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i]),
         "recall_ci95": wilson_interval(int(round(r[i] * s[i])), int(s[i]))}
        for i, lab in enumerate(labels)
    ]
    out["labels"] = [int(x) for x in labels]
    out["confusion_matrix"] = confusion_matrix(y_true, y_pred, labels=labels).tolist()

    # Binary view: does the model separate benign from any attack?
    true_mal = y_true != benign_label
    pred_mal = y_pred != benign_label
    tp = int((true_mal & pred_mal).sum())
    fp = int((~true_mal & pred_mal).sum())
    fn = int((true_mal & ~pred_mal).sum())
    tn = int((~true_mal & ~pred_mal).sum())
    out["binary"] = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
    }
    return out


def measure_latency(preprocessor, model, X_raw: pd.DataFrame, n_single: int, random_state: int) -> dict[str, Any]:
    """Batch throughput plus single-flow latency (preprocessing + inference)."""
    from src.detection.models import predict_proba

    t0 = time.perf_counter()
    predict_proba(model, preprocessor.transform(X_raw))
    batch_s = time.perf_counter() - t0

    rng = np.random.default_rng(random_state)
    idx = rng.choice(len(X_raw), size=min(n_single, len(X_raw)), replace=False)
    single_ms = []
    for i in idx:
        row = X_raw.iloc[[int(i)]]
        t = time.perf_counter()
        predict_proba(model, preprocessor.transform(row))
        single_ms.append((time.perf_counter() - t) * 1000)
    single = np.asarray(single_ms)
    return {
        "batch_rows": int(len(X_raw)),
        "batch_total_ms": batch_s * 1000,
        "batch_per_flow_us": batch_s / max(len(X_raw), 1) * 1e6,
        "single_flow_samples": int(len(single)),
        "single_flow_mean_ms": float(single.mean()) if len(single) else None,
        "single_flow_median_ms": float(np.median(single)) if len(single) else None,
        "single_flow_p95_ms": float(np.percentile(single, 95)) if len(single) else None,
    }
