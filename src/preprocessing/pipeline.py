"""Preprocessing pipeline fitted on training data only."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


class FlowFeatureCleaner(BaseEstimator, TransformerMixin):
    """Coerce to float, map +/-inf to NaN and select informative features.

    During fit, drops columns that are constant in the training data and one of
    every pair of columns whose absolute Pearson correlation exceeds
    `correlation_threshold`. Selection is learned from training data only.
    """

    def __init__(self, correlation_threshold: float | None = 0.99):
        self.correlation_threshold = correlation_threshold

    @staticmethod
    def _coerce(X: pd.DataFrame) -> pd.DataFrame:
        X = X.apply(pd.to_numeric, errors="coerce").astype(float)
        return X.replace([np.inf, -np.inf], np.nan)

    def fit(self, X: pd.DataFrame, y=None):
        X = self._coerce(X)
        self.feature_names_in_ = np.asarray(X.columns, dtype=object)
        nunique = X.nunique(dropna=False)
        self.dropped_constant_ = [c for c in X.columns if nunique[c] <= 1]
        keep = [c for c in X.columns if c not in self.dropped_constant_]

        self.dropped_correlated_ = []
        if self.correlation_threshold is not None and len(keep) > 1:
            corr = X[keep].corr().abs().to_numpy()
            dropped: set[int] = set()
            for i in range(len(keep)):
                if i in dropped:
                    continue
                for j in range(i + 1, len(keep)):
                    if j not in dropped and corr[i, j] > self.correlation_threshold:
                        dropped.add(j)
            self.dropped_correlated_ = [keep[j] for j in sorted(dropped)]
            keep = [c for k, c in enumerate(keep) if k not in dropped]
        self.selected_features_ = keep
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        X = self._coerce(X[list(self.feature_names_in_)])
        return X[self.selected_features_]

    def get_feature_names_out(self, input_features=None):
        return np.asarray(self.selected_features_, dtype=object)


def build_preprocessor(correlation_threshold: float | None = 0.99) -> Pipeline:
    return Pipeline(
        [
            ("clean", FlowFeatureCleaner(correlation_threshold=correlation_threshold)),
            ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
        ]
    ).set_output(transform="pandas")
