"""Classifier factory.

* lightgbm      - gradient boosting for CICFlowMeter tabular features
* extratrees    - randomised tree ensemble, no native dependencies beyond scikit-learn
* random_forest - bagged tree ensemble baseline
* xgboost       - gradient boosting (xgboost-cpu wheel, bundles its own OpenMP)
* pca_ae_nb     - optional reference of the base paper's PCA + Autoencoder + Naive Bayes design
"""
from __future__ import annotations

import warnings
from typing import Any

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.decomposition import PCA
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from src.utils.native import import_lightgbm

MODEL_NAMES = ("lightgbm", "extratrees", "random_forest", "xgboost", "pca_ae_nb")


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


class EncodedXGBClassifier(BaseEstimator, ClassifierMixin):
    """XGBoost needs labels 0..k-1; this keeps the dataset's own class labels in classes_."""

    def __init__(self, params=None, random_state=42):
        self.params = params
        self.random_state = random_state

    def fit(self, X, y, sample_weight=None):
        import xgboost

        self.classes_, encoded = np.unique(np.asarray(y), return_inverse=True)
        self.model_ = xgboost.XGBClassifier(random_state=self.random_state, **(self.params or {}))
        self.model_.fit(X, encoded, sample_weight=sample_weight)
        return self

    @property
    def n_jobs(self):
        return self.model_.get_params()["n_jobs"] if hasattr(self, "model_") else None

    @n_jobs.setter
    def n_jobs(self, value):
        if hasattr(self, "model_"):
            self.model_.set_params(n_jobs=value)

    def predict_proba(self, X):
        return self.model_.predict_proba(X)

    def predict(self, X):
        return self.classes_[np.argmax(self.predict_proba(X), axis=1)]


# Below this many rows, parallel inference costs more in thread start-up than it saves.
PARALLEL_INFERENCE_MIN_ROWS = 2000


def predict_proba(model, X) -> np.ndarray:
    """predict_proba with a worker count suited to the batch size."""
    if hasattr(model, "n_jobs"):
        model.n_jobs = -1 if len(X) >= PARALLEL_INFERENCE_MIN_ROWS else 1
    return model.predict_proba(X)


def decide(proba: np.ndarray, classes, benign_label: int, attack_threshold: float | None = None):
    """Labels and confidences from class probabilities.

    Without a threshold this is argmax. With one, a flow is malicious when the summed
    attack probability (1 - P(benign)) reaches `attack_threshold`; it then gets the
    most probable attack class. The threshold is tuned on validation data only.
    """
    classes = np.asarray(classes)
    if attack_threshold is None or benign_label not in classes or len(classes) < 2:
        idx = proba.argmax(axis=1)
        return classes[idx].astype(int), proba[np.arange(len(proba)), idx]
    b = int(np.flatnonzero(classes == benign_label)[0])
    attack_cols = np.flatnonzero(classes != benign_label)
    best_attack = attack_cols[proba[:, attack_cols].argmax(axis=1)]
    malicious = (1.0 - proba[:, b]) >= attack_threshold
    idx = np.where(malicious, best_attack, b)
    return classes[idx].astype(int), proba[np.arange(len(proba)), idx]


def build_model(name: str, params: dict[str, Any] | None, random_state: int):
    params = dict(params or {})
    if name == "lightgbm":
        lgb = import_lightgbm()
        return lgb.LGBMClassifier(random_state=random_state, **params)
    if name == "extratrees":
        return ExtraTreesClassifier(random_state=random_state, **params)
    if name == "random_forest":
        return RandomForestClassifier(random_state=random_state, **params)
    if name == "xgboost":
        return EncodedXGBClassifier(params, random_state)
    if name == "pca_ae_nb":
        return PcaAutoencoderNB(random_state=random_state, **params)
    raise ValueError(f"unknown model '{name}', expected one of {MODEL_NAMES}")
