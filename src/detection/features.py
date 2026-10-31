"""Feature relevance analysis on training data (validation split), never on the test set.

* mutual information, overall and one-vs-rest per class, on the training part
* permutation importance (macro F1) of a reference ExtraTrees on the validation part
* a top-k sweep over the permutation ranking (a cheap stand-in for recursive
  feature elimination: a handful of refits instead of one per feature)

SHAP is not used: it would add a dependency, and permutation importance answers the
same question (which features the fitted model relies on) for tree ensembles here.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, make_scorer

from src.detection.evaluate import classification_metrics
from src.detection.models import predict_proba
from src.preprocessing.schema import LABEL
from src.preprocessing.splitting import TEST, TRAIN, temporal_split


def _sample(df: pd.DataFrame, benign: int, n_benign: int, rng: np.random.Generator) -> pd.DataFrame:
    """All attack rows plus at most n_benign benign rows (MI cost grows with rows)."""
    b = df[df[LABEL] == benign]
    if len(b) > n_benign:
        b = b.iloc[np.sort(rng.choice(len(b), n_benign, replace=False))]
    return pd.concat([b, df[df[LABEL] != benign]])


def analyse(train_df: pd.DataFrame, features: list[str], cfg: dict[str, Any], fit_model, class_names: dict[int, str],
            imbalance: dict[str, Any] | None, ks: list[int], n_repeats: int = 5) -> dict[str, Any]:
    benign = cfg["benign_label"]
    rs = cfg["training"]["random_state"]
    rng = np.random.default_rng(rs)
    split = temporal_split(train_df, cfg["training"]["threshold_tuning"]["val_fraction"])
    inner, val = train_df[split == TRAIN], train_df[split == TEST]

    pre, model = fit_model(inner, features, "extratrees", cfg, imbalance)
    used = list(pre.named_steps["clean"].selected_features_)

    s = _sample(inner, benign, 20000, rng)
    Xs = pre.transform(s[features])
    ys = s[LABEL].to_numpy()
    mi = mutual_info_classif(Xs, ys, random_state=rs)
    per_class = {}
    for c in sorted(set(ys)):
        if c == benign:
            continue
        mic = mutual_info_classif(Xs, (ys == c).astype(int), random_state=rs)
        top = np.argsort(mic)[::-1][:8]
        per_class[class_names.get(int(c), str(c))] = [[used[i], round(float(mic[i]), 4)] for i in top]

    Xv = pre.transform(val[features])
    yv = val[LABEL].to_numpy()
    labels = [int(c) for c in model.classes_]
    model.n_jobs = -1
    scorer = make_scorer(f1_score, average="macro", labels=labels, zero_division=0)
    pi = permutation_importance(model, Xv, yv, scoring=scorer, n_repeats=n_repeats, random_state=rs, n_jobs=1)
    order = sorted(range(len(used)), key=lambda i: (-pi.importances_mean[i], -mi[i]))
    ranking = [{"feature": used[i], "permutation_mean": float(pi.importances_mean[i]),
                "permutation_std": float(pi.importances_std[i]), "mutual_information": float(mi[i])} for i in order]

    sweep = []
    for k in sorted(set(min(k, len(used)) for k in ks)):
        keep = [r["feature"] for r in ranking[:k]]
        p2, m2 = fit_model(inner, features, "extratrees", cfg, imbalance, keep)
        proba = predict_proba(m2, p2.transform(val[features]))
        pred = np.asarray(m2.classes_)[proba.argmax(axis=1)]
        met = classification_metrics(yv, pred, labels, class_names, benign)
        sweep.append({"k": k, "f1_macro": met["f1_macro"], "recall_macro": met["recall_macro"],
                      "benign_fpr": met["binary"]["false_positive_rate"],
                      "attack_recall": met["binary"]["detection_rate"]})
    best = max(r["f1_macro"] for r in sweep)
    tol = cfg["experiments"]["feature_selection_tolerance"]
    chosen = min((r for r in sweep if r["f1_macro"] >= best - tol), key=lambda r: r["k"])
    return {
        "validation_rows": int(len(val)), "validation_attack_rows": int((yv != benign).sum()),
        "features_after_cleaning": len(used),
        "dropped_constant": pre.named_steps["clean"].dropped_constant_,
        "dropped_correlated": pre.named_steps["clean"].dropped_correlated_,
        "ranking": ranking, "per_class_mutual_information": per_class,
        "sweep": sweep, "selected_k": chosen["k"], "tolerance": tol,
        "selected_features": [r["feature"] for r in ranking[:chosen["k"]]],
    }
