"""Classifier factory.

* lightgbm   - primary candidate for CICFlowMeter tabular features
* extratrees - fallback with no native dependencies beyond scikit-learn
* pca_ae_nb  - optional reference of the base paper's PCA + Autoencoder + Naive Bayes design
"""
from __future__ import annotations

import warnings
from typing import Any

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.decomposition import PCA
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from src.utils.native import import_lightgbm

MODEL_NAMES = ("lightgbm", "extratrees", "pca_ae_nb")


class PcaAutoencoderNB(BaseEstimator, ClassifierMixin):
    """Reference pipeline: scale -> PCA -> autoencoder bottleneck -> Gaussian NB.

    The autoencoder is an MLPRegressor trained to reconstruct the PCA components
    (hidden -> bottleneck -> hidden); the bottleneck activations are the features
    passed to Naive Bayes. A signed log1p transform is applied first because
    CICFlowMeter features are extremely heavy-tailed; this is an implementation
    choice of this prototype, not taken from the paper.
    """

    def __init__(self, pca_components=20, hidden_units=32, bottleneck_units=8, max_iter=80,
                 log_transform=True, random_state=42):
        self.pca_components = pca_components
        self.hidden_units = hidden_units
        self.bottleneck_units = bottleneck_units
        self.max_iter = max_iter
        self.log_transform = log_transform
        self.random_state = random_state

    def _prepare(self, X) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        return np.sign(X) * np.log1p(np.abs(X)) if self.log_transform else X

    def _encode(self, P: np.ndarray) -> np.ndarray:
        a = P
        for W, b in zip(self.autoencoder_.coefs_[:2], self.autoencoder_.intercepts_[:2]):
            a = np.maximum(a @ W + b, 0.0)
        return a

    def _bottleneck(self, X) -> np.ndarray:
        Z = self.scaler_.transform(self._prepare(X))
        P = self.pca_scaler_.transform(self.pca_.transform(Z))
        return self._encode(P)

    def fit(self, X, y):
        Z = self._prepare(X)
        self.scaler_ = StandardScaler().fit(Z)
        Z = self.scaler_.transform(Z)
        self.pca_ = PCA(n_components=min(self.pca_components, Z.shape[1]), random_state=self.random_state).fit(Z)
        P = self.pca_.transform(Z)
        self.pca_scaler_ = StandardScaler().fit(P)
        P = self.pca_scaler_.transform(P)
        self.autoencoder_ = MLPRegressor(
            hidden_layer_sizes=(self.hidden_units, self.bottleneck_units, self.hidden_units),
            activation="relu", max_iter=self.max_iter, early_stopping=True, random_state=self.random_state,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            self.autoencoder_.fit(P, P)
        self.nb_ = GaussianNB().fit(self._encode(P), y)
        self.classes_ = self.nb_.classes_
        return self

    def predict_proba(self, X):
        return self.nb_.predict_proba(self._bottleneck(X))

    def predict(self, X):
        return self.classes_[np.argmax(self.predict_proba(X), axis=1)]


# Below this many rows, parallel inference costs more in thread start-up than it saves.
PARALLEL_INFERENCE_MIN_ROWS = 2000


def predict_proba(model, X) -> np.ndarray:
    """predict_proba with a worker count suited to the batch size."""
    if hasattr(model, "n_jobs"):
        model.n_jobs = -1 if len(X) >= PARALLEL_INFERENCE_MIN_ROWS else 1
    return model.predict_proba(X)


def build_model(name: str, params: dict[str, Any] | None, random_state: int):
    params = dict(params or {})
    if name == "lightgbm":
        lgb = import_lightgbm()
        return lgb.LGBMClassifier(random_state=random_state, **params)
    if name == "extratrees":
        return ExtraTreesClassifier(random_state=random_state, **params)
    if name == "pca_ae_nb":
        return PcaAutoencoderNB(random_state=random_state, **params)
    raise ValueError(f"unknown model '{name}', expected one of {MODEL_NAMES}")
