"""Train and evaluate a flow classifier on the Kubernetes misuse-detection dataset.

Examples:
    python -m src.detection.train --model lightgbm
    python -m src.detection.train --model extratrees
    python -m src.detection.train --model lightgbm --label-policy attack_focused
    python -m src.detection.train --model lightgbm --split random     # optimistic comparison
    python -m src.detection.train --model pca_ae_nb                   # base-paper reference
    python -m src.detection.train --model extratrees --label-policy evidence --imbalance sqrt --tune-threshold
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn

from src.detection.evaluate import classification_metrics, measure_latency
from src.detection import imbalance as imb
from src.detection.models import MODEL_NAMES, build_model, decide, predict_proba
from src.preprocessing.cleaning import (
    background_like_mask,
    background_service_signatures,
    data_quality_report,
    label_noise_analysis,
)
from src.preprocessing.dataset import CAPTURE, capture_prefix, dataset_manifest, load_dataset
from src.preprocessing.labeling import STATUS, label_dataset, supported_classes, trainable_mask
from src.preprocessing.pipeline import build_preprocessor
from src.preprocessing.schema import DST_IP, DST_PORT, PROTOCOL, SRC_IP, SRC_PORT, TIMESTAMP, LABEL
from src.preprocessing.splitting import TEST, TRAIN, make_split, temporal_split
from src.utils.config import class_names, get_path, load_config
from src.utils.logging_setup import get_logger
from src.utils.native import ensure_libgomp

log = get_logger(__name__)
SPLIT = "_split"


def feature_columns(df: pd.DataFrame, cfg: dict[str, Any]) -> list[str]:
    drop = set(cfg["features"]["drop_columns"]) | set(cfg["features"]["exclude_columns"])
    cols = [c for c in df.columns if not c.startswith("_") and c != LABEL and c not in drop]
    non_numeric = [c for c in cols if not pd.api.types.is_numeric_dtype(df[c])]
    if non_numeric:
        raise ValueError(f"non-numeric feature columns: {non_numeric}")
    return cols


def fit_model(train_df: pd.DataFrame, features: list[str], model_name: str, cfg: dict[str, Any],
              imbalance: dict[str, Any] | None = None, keep_features: list[str] | None = None,
              params: dict[str, Any] | None = None, return_report: bool = False):
    """Fit preprocessing and the classifier on training rows only.

    imbalance=None keeps the configured model parameters as they are (including
    any class_weight), which reproduces the original models. With a strategy spec,
    class_weight is removed from the parameters and the strategy is applied instead.
    """
    pre = build_preprocessor(cfg["features"]["correlation_threshold"], keep_features)
    X = pre.fit_transform(train_df[features])
    y = train_df[LABEL].to_numpy()
    params = dict(cfg["models"].get(model_name) or {}) if params is None else dict(params)
    weight, report = None, {"strategy": "config"}
    if imbalance is not None:
        params.pop("class_weight", None)
        X, y, weight, report = imb.apply(X, y, imbalance, cfg["benign_label"], cfg["training"]["random_state"])
    model = build_model(model_name, params, cfg["training"]["random_state"])
    if weight is not None:
        model.fit(X, y, sample_weight=weight)
    else:
        model.fit(X, y)
    return (pre, model, report) if return_report else (pre, model)


def predict_labels(pre, model, frame: pd.DataFrame, features: list[str], attack_threshold: float | None = None,
                   benign_label: int = 0) -> tuple[np.ndarray, np.ndarray]:
    proba = predict_proba(model, pre.transform(frame[features]))
    return decide(proba, model.classes_, benign_label, attack_threshold)


def tune_threshold(train_df: pd.DataFrame, features: list[str], model_name: str, cfg: dict[str, Any],
                   imbalance: dict[str, Any] | None = None, keep_features: list[str] | None = None,
                   params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Choose the attack-probability threshold on a validation split of the training data.

    The validation part is the latest `val_fraction` of every training capture. The
    test set is never touched. Objective: highest validation macro F1 among thresholds
    whose validation benign FPR stays within `max_val_benign_fpr`. Plain argmax
    (threshold None) competes as well.
    """
    tt = cfg["training"]["threshold_tuning"]
    benign = cfg["benign_label"]
    split = temporal_split(train_df, tt["val_fraction"])
    inner = train_df[split == TRAIN]
    val = train_df[split == TEST]
    pre, model = fit_model(inner, features, model_name, cfg, imbalance, keep_features, params)
    proba = predict_proba(model, pre.transform(val[features]))
    labels = [int(c) for c in model.classes_]
    y = val[LABEL].to_numpy()
    rows = []
    for t in [None, *tt["grid"]]:
        pred, _ = decide(proba, model.classes_, benign, t)
        m = classification_metrics(y, pred, labels, {}, benign)
        rows.append({"threshold": t, "f1_macro": m["f1_macro"], "benign_fpr": m["binary"]["false_positive_rate"],
                     "attack_recall": m["binary"]["detection_rate"]})
    ok = [r for r in rows if (r["benign_fpr"] or 0.0) <= tt["max_val_benign_fpr"]]
    if not ok:
        ok = [min(rows, key=lambda r: r["benign_fpr"] or 0.0)]
    best = max(ok, key=lambda r: (round(r["f1_macro"], 6), r["threshold"] or 0.5))
    return {"attack_threshold": best["threshold"], "validation_rows": int(len(val)),
            "validation_attack_rows": int((y != benign).sum()), "chosen": best, "grid": rows,
            "max_val_benign_fpr": tt["max_val_benign_fpr"]}


def apply_label_policy(df: pd.DataFrame, policy: str, signatures: set[str], cfg: dict[str, Any]):
    benign = cfg["benign_label"]
    report: dict[str, Any] = {"policy": policy}
    if policy == "dataset":
        return df, report
    if policy == "evidence":
        # Per-flow evidence labels (src/preprocessing/labeling.py). Infrastructure
        # signatures come from the training part of the background capture only.
        bg_prefix = cfg["dataset"]["background_capture_prefix"]
        bg_train = df[(df[CAPTURE].map(capture_prefix) == bg_prefix) & (df[SPLIT] == TRAIN)]
        labelled = label_dataset(df, cfg, signature_source=bg_train)
        supported, counts = supported_classes(labelled, cfg)
        keep = trainable_mask(labelled, cfg) & labelled[LABEL].isin([benign, *supported])
        names = class_names(cfg)
        report.update(
            status_counts={k: int(v) for k, v in labelled[STATUS].value_counts().items()},
            attack_evidence_counts=counts, trained_attack_classes=supported,
            untrained_classes={c: names[c] for c in counts if c not in supported},
            background_action=cfg["labeling"]["background_action"],
            dropped_rows=int((~keep).sum()),
        )
        return labelled.loc[keep], report
    if policy != "attack_focused":
        raise ValueError(f"unknown label policy: {policy}")
    if not signatures:
        raise ValueError("attack_focused policy needs the background capture to derive service signatures")
    drop = (df[LABEL] != benign) & background_like_mask(df, signatures)
    df = df.loc[~drop]
    counts = df[LABEL].value_counts()
    min_samples = cfg["training"]["attack_focused"]["min_class_samples"]
    small = sorted(int(c) for c in counts[counts < min_samples].index)
    names = class_names(cfg)
    report.update(
        dropped_background_like_attack_flows=int(drop.sum()),
        min_class_samples=min_samples,
        dropped_classes={int(c): names[c] for c in small},
        dropped_class_remaining_flows={int(c): int(counts[c]) for c in small},
    )
    return df.loc[~df[LABEL].isin(small)], report


def benign_holdout_eval(df: pd.DataFrame, features: list[str], capture: str, model_name: str,
                        cfg: dict[str, Any], imbalance: dict[str, Any] | None = None,
                        keep_features: list[str] | None = None, params: dict[str, Any] | None = None,
                        attack_threshold: float | None = None) -> dict[str, Any]:
    """Retrain without one whole benign capture and measure false positives on it."""
    benign = cfg["benign_label"]
    hold = df[df[CAPTURE] == capture]
    if hold.empty:
        return {"skipped": f"capture {capture} not present"}
    if (hold[LABEL] != benign).any():
        return {"skipped": f"capture {capture} is not benign"}
    train_df = df[(df[SPLIT] == TRAIN) & (df[CAPTURE] != capture)].drop_duplicates(subset=features + [LABEL])
    pre, model = fit_model(train_df, features, model_name, cfg, imbalance, keep_features, params)
    pred, _ = predict_labels(pre, model, hold, features, attack_threshold, benign)
    fp = pred != benign
    names = class_names(cfg)
    fp_classes = pd.Series(pred[fp]).value_counts()
    return {
        "capture": capture,
        "flows": int(len(hold)),
        "false_positives": int(fp.sum()),
        "false_positive_rate": float(fp.mean()),
        "false_positive_classes": {names[int(k)]: int(v) for k, v in fp_classes.items()},
    }


def lab_eval_metrics(pre, model, lab: pd.DataFrame, features: list[str], cfg: dict[str, Any],
                     attack_threshold: float | None = None) -> dict[str, Any]:
    """Benign false-positive rate and attack detection on a held-out lab set."""
    benign = cfg["benign_label"]
    pred, conf = predict_labels(pre, model, lab, features, attack_threshold, benign)
    y = lab[LABEL].to_numpy()
    is_b, mal = y == benign, pred != benign
    out: dict[str, Any] = {"flows": int(len(lab)), "benign_flows": int(is_b.sum()), "attack_flows": int((~is_b).sum()),
                           "benign_fpr": float(mal[is_b].mean()) if is_b.any() else None,
                           "benign_fpr_conf_ge_0.9": float((mal & (conf >= 0.9))[is_b].mean()) if is_b.any() else None}
    if (~is_b).any():
        out["attack_detected_any_class"] = float(mal[~is_b].mean())
        out["attack_detected_correct_class"] = float((pred == y)[~is_b].mean())
        out["attack_correct_conf_ge_0.9"] = float(((pred == y) & (conf >= 0.9))[~is_b].mean())
    return out


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")


def update_registry(models_dir: Path, name: str, entry: dict[str, Any]) -> None:
    reg_path = models_dir / "registry.json"
    registry = json.loads(reg_path.read_text()) if reg_path.exists() else {}
    registry[name] = entry
    _write_json(reg_path, registry)


def run_training(
    model_name: str,
    label_policy: str | None = None,
    split_method: str | None = None,
    name: str | None = None,
    cfg: dict[str, Any] | None = None,
    df: pd.DataFrame | None = None,
    models_dir: Path | None = None,
    processed_dir: Path | None = None,
    benign_holdout: str | None = "config",
    lab_train: list[str] | None = None,
    lab_eval: list[str] | None = None,
    imbalance: dict[str, Any] | None = None,
    keep_features: list[str] | None = None,
    model_params: dict[str, Any] | None = None,
    tune: bool = False,
) -> dict[str, Any]:
    cfg = cfg or load_config()
    tr = cfg["training"]
    label_policy = label_policy or tr["label_policy"]
    split_method = split_method or tr["split"]
    lab_train, lab_eval = lab_train or [], lab_eval or []
    name = name or (f"{model_name}_{label_policy}" + ("" if split_method == "temporal" else f"_{split_method}")
                    + ("_lab" if lab_train else ""))
    models_dir = models_dir or get_path("models_dir", cfg)
    processed_dir = processed_dir or get_path("processed_dir", cfg)
    benign = cfg["benign_label"]
    names = class_names(cfg)
    started = time.perf_counter()
    libgomp = ensure_libgomp() if model_name == "lightgbm" else None

    manifest = None
    if df is None:
        df = load_dataset(cfg)
        manifest = dataset_manifest(cfg)
    features = feature_columns(df, cfg)
    quality = data_quality_report(df, features)
    log.info("dataset: %d flows, %d candidate features", len(df), len(features))

    df = df.assign(**{SPLIT: make_split(df, split_method, tr["test_fraction"], tr["random_state"])})

    # Infrastructure service signatures are learned from the training portion of
    # the pure background capture only, then used for the noise analysis/policy.
    bg_prefix = cfg["dataset"]["background_capture_prefix"]
    bg_train = df[(df[CAPTURE].map(capture_prefix) == bg_prefix) & (df[SPLIT] == TRAIN)]
    signatures = (
        background_service_signatures(bg_train, tr["attack_focused"]["min_service_port_count"])
        if len(bg_train) else set()
    )
    noise = label_noise_analysis(df, signatures, benign) if signatures else {"skipped": "no background capture"}
    df, policy_report = apply_label_policy(df, label_policy, signatures, cfg)

    # Verified lab flows (controlled benign traffic) are added to training only, so
    # the dataset test set stays identical and comparable across models.
    lab_report: dict[str, Any] = {}
    if lab_train:
        from src.preprocessing.lab_data import load_lab_set

        dataset_cols = list(df.columns)
        for set_name in lab_train:
            lab = load_lab_set(set_name, cfg)
            missing = [c for c in features if c not in lab.columns]
            if missing:
                raise ValueError(f"lab set {set_name} lacks features {missing}")
            lab = lab[[c for c in dataset_cols if c in lab.columns]].assign(**{SPLIT: TRAIN})
            lab_report[set_name] = {int(k): int(v) for k, v in lab[LABEL].value_counts().items()}
            df = pd.concat([df, lab], ignore_index=True)

    train_df = df[df[SPLIT] == TRAIN]
    test_df = df[df[SPLIT] == TEST]
    train_rows_before = len(train_df)
    train_df = train_df.drop_duplicates(subset=features + [LABEL])
    missing_in_train = sorted(set(test_df[LABEL]) - set(train_df[LABEL]))
    if missing_in_train:
        raise ValueError(f"classes {missing_in_train} appear in test but not in train")

    train_hashes = set(pd.util.hash_pandas_object(train_df[features], index=False))
    test_hashes = pd.util.hash_pandas_object(test_df[features], index=False)
    identical_in_train = int(test_hashes.isin(train_hashes).sum())

    decision: dict[str, Any] = {"attack_threshold": None, "tuned": False}
    if tune:
        decision = {**tune_threshold(train_df, features, model_name, cfg, imbalance, keep_features, model_params),
                    "tuned": True}
    threshold = decision["attack_threshold"]

    t_fit = time.perf_counter()
    pre, model, imbalance_report = fit_model(train_df, features, model_name, cfg, imbalance, keep_features,
                                             model_params, return_report=True)
    fit_seconds = time.perf_counter() - t_fit
    labels = [int(c) for c in model.classes_]

    y_pred, conf = predict_labels(pre, model, test_df, features, threshold, benign)
    metrics = classification_metrics(test_df[LABEL].to_numpy(), y_pred, labels, names, benign)
    latency = measure_latency(pre, model, test_df[features], tr["latency_samples"], tr["random_state"])

    lab_results = {}
    if lab_eval:
        from src.preprocessing.lab_data import load_lab_set

        for set_name in lab_eval:
            if set_name in lab_train:
                raise ValueError(f"lab set {set_name} is used for training and cannot be an evaluation set")
            lab_results[set_name] = lab_eval_metrics(pre, model, load_lab_set(set_name, cfg), features, cfg,
                                                     threshold)

    holdout_capture = tr.get("benign_holdout_capture") if benign_holdout == "config" else benign_holdout
    holdout = (
        benign_holdout_eval(df, features, holdout_capture, model_name, cfg, imbalance, keep_features, model_params,
                            threshold) if holdout_capture
        else {"skipped": "disabled"}
    )

    out = models_dir / name
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(pre, out / "preprocessor.joblib")
    joblib.dump(model, out / "model.joblib")
    cleaner = pre.named_steps["clean"]
    _write_json(out / "decision.json", decision)
    _write_json(out / "class_mapping.json", {
        "benign_label": benign,
        "model_classes": {str(c): names[c] for c in labels},
        "all_classes": {str(k): v for k, v in names.items()},
    })
    _write_json(out / "feature_schema.json", {
        "input_features": features,
        "selected_features": cleaner.selected_features_,
        "dropped_constant": cleaner.dropped_constant_,
        "dropped_correlated": cleaner.dropped_correlated_,
        "drop_columns": cfg["features"]["drop_columns"],
        "exclude_columns": cfg["features"]["exclude_columns"],
        "metadata_columns": ["Flow ID", SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL, TIMESTAMP],
        "max_missing_feature_fraction": cfg["features"]["max_missing_feature_fraction"],
    })
    split_counts = (
        df.groupby([CAPTURE, SPLIT]).size().unstack(fill_value=0).astype(int).to_dict(orient="index")
    )
    result = {
        "name": name,
        "model": model_name,
        "label_policy": label_policy,
        "split": split_method,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "test": metrics,
        "latency": latency,
        "benign_holdout": holdout,
        "lab_training_sets": lab_report,
        "lab_evaluation": lab_results,
        "leakage_checks": {
            "train_rows_before_dedup": int(train_rows_before),
            "train_rows_after_dedup": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "test_rows_with_identical_train_feature_vector": identical_in_train,
            "dropped_identifier_columns": cfg["features"]["drop_columns"],
        },
        "label_policy_report": policy_report,
        "imbalance": imbalance_report,
        "keep_features": keep_features,
        "decision": {k: v for k, v in decision.items() if k != "grid"},
        "model_bytes": sum(f.stat().st_size for f in out.glob("*.joblib")),
        "label_noise_analysis": noise,
        "split_counts_by_capture": split_counts,
        "fit_seconds": fit_seconds,
        "total_seconds": time.perf_counter() - started,
    }
    _write_json(out / "metrics.json", result)
    _write_json(out / "training_config.json", {
        "model": model_name,
        "model_params": model_params if model_params is not None else cfg["models"].get(model_name),
        "imbalance": imbalance,
        "keep_features": keep_features,
        "attack_threshold": threshold,
        "label_policy": label_policy,
        "split": split_method,
        "test_fraction": tr["test_fraction"],
        "random_state": tr["random_state"],
        "correlation_threshold": cfg["features"]["correlation_threshold"],
        "benign_holdout_capture": holdout_capture,
        "lab_train_sets": lab_train,
        "lab_eval_sets": lab_eval,
        "dataset_manifest": manifest,
        "environment": {
            "python": platform.python_version(),
            "sklearn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "lightgbm": __import__("lightgbm").__version__ if model_name == "lightgbm" else None,
            "xgboost": __import__("xgboost").__version__ if model_name == "xgboost" else None,
            "libgomp": libgomp,
        },
    })
    pd.DataFrame(metrics["confusion_matrix"], index=[names[c] for c in labels],
                 columns=[names[c] for c in labels]).to_csv(out / "confusion_matrix.csv")

    processed_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({
        "capture": test_df[CAPTURE].to_numpy(),
        "true_label": test_df[LABEL].to_numpy(),
        "predicted_label": y_pred,
        "confidence": conf,
    }).to_csv(processed_dir / f"{name}_test_predictions.csv", index=False)
    _write_json(processed_dir / "data_quality_report.json", quality)

    update_registry(models_dir, name, {
        "model": model_name, "label_policy": label_policy, "split": split_method,
        "trained_at": result["trained_at"], "classes": len(labels),
        "accuracy": metrics["accuracy"], "f1_macro": metrics["f1_macro"], "f1_weighted": metrics["f1_weighted"],
        "benign_holdout_fpr": holdout.get("false_positive_rate"),
        "recall_macro": metrics["recall_macro"],
        "attack_recall": metrics["binary"]["detection_rate"],
        "benign_fpr": metrics["binary"]["false_positive_rate"],
        "attack_threshold": threshold,
        "imbalance": (imbalance or {}).get("strategy", "config"),
        "lab_train_sets": lab_train,
        "lab_evaluation": lab_results,
    })
    log.info("saved %s: acc=%.4f macroF1=%.4f weightedF1=%.4f (fit %.1fs)", name,
             metrics["accuracy"], metrics["f1_macro"], metrics["f1_weighted"], fit_seconds)
    return result


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", choices=MODEL_NAMES, default=load_config()["training"]["default_model"])
    ap.add_argument("--label-policy", choices=("dataset", "attack_focused", "evidence"))
    ap.add_argument("--imbalance", choices=imb.STRATEGIES, help="override the configured class weighting")
    ap.add_argument("--tune-threshold", action="store_true", help="tune the attack threshold on validation data")
    ap.add_argument("--split", choices=("temporal", "random"))
    ap.add_argument("--name", help="output directory name under models/")
    ap.add_argument("--no-holdout", action="store_true", help="skip the benign-capture holdout evaluation")
    ap.add_argument("--lab-train", action="append", help="lab set (data/lab/<name>) added to training")
    ap.add_argument("--lab-eval", action="append", help="held-out lab set to evaluate on")
    args = ap.parse_args(argv)
    res = run_training(args.model, args.label_policy, args.split, args.name,
                       benign_holdout=None if args.no_holdout else "config",
                       lab_train=args.lab_train, lab_eval=args.lab_eval,
                       imbalance={"strategy": args.imbalance} if args.imbalance else None, tune=args.tune_threshold)
    t = res["test"]
    print(f"\n{res['name']}: accuracy={t['accuracy']:.4f} macroF1={t['f1_macro']:.4f} "
          f"weightedF1={t['f1_weighted']:.4f} binaryFPR={t['binary']['false_positive_rate']}")
    print(f"{'class':28s} {'prec':>6s} {'rec':>6s} {'f1':>6s} {'n':>6s}")
    for pc in t["per_class"]:
        print(f"{pc['name']:28s} {pc['precision']:6.3f} {pc['recall']:6.3f} {pc['f1']:6.3f} {pc['support']:6d}")
    print("benign holdout:", res["benign_holdout"])
    for set_name, m in res["lab_evaluation"].items():
        print(f"lab eval {set_name}:", {k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()})
    print("latency:", {k: round(v, 3) if isinstance(v, float) else v for k, v in res["latency"].items()})


if __name__ == "__main__":
    main()
