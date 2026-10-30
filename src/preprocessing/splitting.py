"""Train/test splitting strategies.

Every attack class in the dataset comes from exactly one capture, so a split by
capture cannot place a class in both train and test. The default `temporal`
split instead holds out the *last* part of every capture, which avoids mixing
neighbouring (near-identical) flows across the split the way a random split does.
"""
from __future__ import annotations

import pandas as pd
from sklearn.model_selection import train_test_split

from src.preprocessing.dataset import CAPTURE, TS
from src.preprocessing.schema import LABEL

TRAIN = "train"
TEST = "test"


def temporal_split(df: pd.DataFrame, test_fraction: float) -> pd.Series:
    """Per capture, the latest `test_fraction` of flows (by start time) go to test."""
    split = pd.Series(TRAIN, index=df.index, dtype=object)
    for _, g in df.groupby(CAPTURE):
        if len(g) < 2:
            continue
        ordered = g.sort_values(TS, kind="stable", na_position="first").index
        n_test = max(1, int(round(len(g) * test_fraction)))
        split.loc[ordered[-n_test:]] = TEST
    return split


def random_split(df: pd.DataFrame, test_fraction: float, random_state: int) -> pd.Series:
    """Stratified random split. Optimistic on this dataset; kept for comparison."""
    _, test_idx = train_test_split(
        df.index, test_size=test_fraction, stratify=df[LABEL], random_state=random_state
    )
    split = pd.Series(TRAIN, index=df.index, dtype=object)
    split.loc[test_idx] = TEST
    return split


def make_split(df: pd.DataFrame, method: str, test_fraction: float, random_state: int) -> pd.Series:
    if method == "temporal":
        return temporal_split(df, test_fraction)
    if method == "random":
        return random_split(df, test_fraction, random_state)
    raise ValueError(f"unknown split method: {method}")
