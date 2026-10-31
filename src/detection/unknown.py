"""Unknown-traffic handling on top of the per-flow classifier.

A flow is reported as UNKNOWN ("Unknown / Requires Investigation") instead of
benign or attack when any enabled check fires:

  unfamiliar_service  the destination service had fewer than `min_benign_service_flows`
                      benign training flows: the model has never seen that
                      application's normal traffic, so an attack verdict on it
                      is not trustworthy
  low_confidence      the winning class probability is below `min_confidence`
  out_of_distribution the distance to the nearest training flows (log-scaled,
                      standardised features) exceeds a quantile of the same
                      distance on validation flows

Unknown flows are never counted as detections of an attack class, and the
deception controller does not act on them (is_malicious stays 0).
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors

from src.preprocessing.labeling import orient
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, PROTOCOL, SRC_IP, SRC_PORT

UNKNOWN = "unknown"
UNKNOWN_CLASS = "Unknown / Requires Investigation"
REASONS = ("unfamiliar_service", "low_confidence", "out_of_distribution")


def service_keys(df: pd.DataFrame) -> pd.Series:
    """'proto:service port' per flow; '?' when the flow metadata is missing."""
    cols = [SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL]
    if any(c not in df.columns for c in cols) or df.empty:
        return pd.Series("?", index=df.index)
    meta = df[cols].copy()
    for c in (SRC_PORT, DST_PORT, PROTOCOL):
        meta[c] = pd.to_numeric(meta[c], errors="coerce").fillna(-1)
    o = orient(meta)
    return o["proto"].astype(str) + ":" + o["service"].astype(str)


def benign_service_profile(train_df: pd.DataFrame, benign_label: int) -> dict[str, int]:
    """Benign training flows per (protocol:service port)."""
    keys = service_keys(train_df[train_df[LABEL] == benign_label])
    return {k: int(v) for k, v in keys.value_counts().items()}


class NoveltyScorer:
    """Mean distance to the k nearest training flows in a log-scaled, standardised space."""

    def __init__(self, k: int = 5, sample: int = 20000, random_state: int = 42):
        self.k, self.sample, self.random_state = k, sample, random_state

    @staticmethod
    def _log(X: np.ndarray) -> np.ndarray:
        return np.sign(X) * np.log1p(np.abs(X))

    def fit(self, X: pd.DataFrame, y: np.ndarray, benign_label: int) -> "NoveltyScorer":
        rng = np.random.default_rng(self.random_state)
        Z = self._log(X.to_numpy(dtype=float))
        # keep every attack row, subsample benign rows
        b = np.flatnonzero(y == benign_label)
        keep = np.concatenate([np.flatnonzero(y != benign_label),
                               rng.choice(b, min(len(b), self.sample), replace=False)])
        Z = Z[keep]
        self.mean_, self.scale_ = Z.mean(axis=0), Z.std(axis=0) + 1e-9
        self.nn_ = NearestNeighbors(n_neighbors=self.k).fit((Z - self.mean_) / self.scale_)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        Z = (self._log(X.to_numpy(dtype=float)) - self.mean_) / self.scale_
        d, _ = self.nn_.kneighbors(Z)
        return d.mean(axis=1)

    def calibrate(self, X_val: pd.DataFrame, quantile: float) -> float:
        self.threshold_ = float(np.quantile(self.score(X_val), quantile))
        return self.threshold_


def assess(labels: np.ndarray, confidence: np.ndarray, services: pd.Series, benign_label: int,
           ucfg: dict[str, Any], profile: dict[str, int] | None = None,
           novelty: np.ndarray | None = None, novelty_threshold: float | None = None) -> tuple[np.ndarray, np.ndarray]:
    """(status per flow: benign | attack | unknown, reason or '')."""
    attack = labels != benign_label
    status = np.where(attack, "attack", "benign").astype(object)
    reason = np.full(len(labels), "", dtype=object)
    checks = ucfg["checks"]
    if "out_of_distribution" in checks and novelty is not None and novelty_threshold is not None:
        m = novelty > novelty_threshold
        status[m], reason[m] = UNKNOWN, "out_of_distribution"
    if "low_confidence" in checks:
        m = confidence < ucfg["min_confidence"]
        status[m], reason[m] = UNKNOWN, "low_confidence"
    if "unfamiliar_service" in checks and profile is not None:
        known = services.map(lambda s: profile.get(s, 0) >= ucfg["min_benign_service_flows"]).to_numpy()
        m = attack & ~known
        status[m], reason[m] = UNKNOWN, "unfamiliar_service"
    return status, reason


def build_profile(model_name: str) -> dict[str, int]:
    """Write models/<name>/service_profile.json from the comparison protocol's training pool
    (the data the compared candidates, including the selected model, were trained on)."""
    import json

    from src.detection.experiments import Protocol
    from src.utils.config import get_path, load_config

    cfg = load_config()
    profile = benign_service_profile(Protocol(cfg).training_pool(), cfg["benign_label"])
    (get_path("models_dir", cfg) / model_name / "service_profile.json").write_text(json.dumps(profile, indent=2))
    return profile


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="build the benign service profile of a trained model")
    ap.add_argument("--build", required=True, metavar="MODEL")
    prof = build_profile(ap.parse_args().build)
    print({k: v for k, v in sorted(prof.items(), key=lambda kv: -kv[1])[:15]}, f"... {len(prof)} services")
