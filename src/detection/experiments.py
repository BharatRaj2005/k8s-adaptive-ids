"""Compare candidate classifiers under one validation protocol.

    python -m src.detection.experiments                 # all candidates in config `experiments`
    python -m src.detection.experiments --only v2_et_sqrt --skip-grouped

Protocol (identical for every candidate, see reports/model_comparison.md):
  1. Evidence labels (src/preprocessing/labeling.py), temporal split: the latest
     25 % of every capture is the test set. Ambiguous flows are excluded.
  2. Lab sets in `experiments.lab_train_sets` join the training part only.
  3. Attack threshold tuned on a validation split of the training part.
  4. Test-set metrics, plus every lab set in `experiments.lab_eval_sets`.
  5. Benign leave-one-capture-out: retrain without one whole benign capture,
     measure false positives on it (threshold re-tuned inside the fold).
  6. Recon leave-one-run-out over independent recon executions (the dataset's
     recon capture and the lab recon runs): retrain without the run, measure
     recall and false positives on it (threshold re-tuned inside the fold).
  7. Resource profile of the saved model in a fresh process.

The existing baseline model is scored on the same test rows and lab sets
without retraining. Its grouped evaluations retrain its original recipe
(published labels, original parameters) and score against the evidence labels.
"""
from __future__ import annotations

import argparse
import copy
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.detection.evaluate import classification_metrics
from src.detection.features import analyse
from src.detection.predictor import FlowPredictor
from src.detection.profile_model import profile_in_subprocess
from src.detection.train import (
    SPLIT, apply_label_policy, feature_columns, fit_model, predict_labels, run_training, tune_threshold,
)
from src.preprocessing.dataset import CAPTURE, capture_prefix, load_dataset
from src.preprocessing.lab_data import load_lab_set, load_manifest
from src.preprocessing.labeling import ORIGINAL_LABEL, STATUS
from src.preprocessing.schema import LABEL
from src.preprocessing.splitting import TEST, TRAIN, make_split
from src.utils.config import class_names, get_path, load_config
from src.utils.logging_setup import get_logger

log = get_logger(__name__)
RUN = "_run"


def _imbalance(spec: Any) -> dict[str, Any] | None:
    if spec is None or spec == "config":
        return None
    return {"strategy": spec} if isinstance(spec, str) else dict(spec)


def _lab(name: str, cfg: dict[str, Any], columns: list[str]) -> pd.DataFrame:
    lab = load_lab_set(name, cfg)
    return lab[[c for c in columns if c in lab.columns]].assign(**{SPLIT: TRAIN, RUN: f"lab:{name}"})


class Protocol:
    """Data shared by all candidates: split, both label views, lab sets."""

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        ex = cfg["experiments"]
        self.raw = load_dataset(cfg)
        self.features = feature_columns(self.raw, cfg)
        base = self.raw.assign(**{SPLIT: make_split(self.raw, "temporal", cfg["training"]["test_fraction"],
                                                    cfg["training"]["random_state"])})
        base[RUN] = "dataset:" + base[CAPTURE].map(capture_prefix)
        self.evidence, self.policy_report = apply_label_policy(base, "evidence", set(), cfg)
        self.published = base
        cols = list(self.evidence.columns)
        self.lab_train = {n: _lab(n, cfg, cols) for n in ex["lab_train_sets"]}
        self.lab_eval = {n: load_lab_set(n, cfg) for n in ex["lab_eval_sets"]}
        self.recon_runs = ex["recon_runs"]
        self.recon_lab = {n: _lab(n, cfg, cols) for n in self.recon_runs if not n.startswith("dataset:")}
        self.test = self.evidence[self.evidence[SPLIT] == TEST]
        self.labels = sorted(int(c) for c in self.evidence[LABEL].unique())

    def training_pool(self, published: bool = False, extra: list[pd.DataFrame] | None = None,
                      lab_names: list[str] | None = None) -> pd.DataFrame:
        frame = self.published if published else self.evidence
        if published:
            # the original recipe never saw evidence labels; keep only its own training rows
            frame = frame.drop(columns=[c for c in (STATUS, ORIGINAL_LABEL) if c in frame.columns])
        labs = [d for n, d in self.lab_train.items() if lab_names is None or n in lab_names]
        parts = [frame[frame[SPLIT] == TRAIN], *labs, *(extra or [])]
        return pd.concat(parts, ignore_index=True).drop_duplicates(subset=self.features + [LABEL])


def fold_fit(pool: pd.DataFrame, features: list[str], cand: dict[str, Any], cfg: dict[str, Any]):
    imb = _imbalance(cand.get("imbalance"))
    params = cand.get("params_full")
    keep = cand.get("keep_features")
    thr = tune_threshold(pool, features, cand["model"], cfg, imb, keep, params)["attack_threshold"] \
        if cand.get("tune", True) else None
    pre, model = fit_model(pool, features, cand["model"], cfg, imb, keep, params)
    return pre, model, thr


def grouped(proto: Protocol, cand: dict[str, Any], published: bool = False) -> dict[str, Any]:
    cfg, feats, benign = proto.cfg, proto.features, cfg_benign(proto.cfg)
    labs = cand.get("lab_train_sets")          # None = the configured lab training sets
    use_runs = cand.get("train_on_recon_runs", True)
    out: dict[str, Any] = {"benign_loco": [], "recon_loro": []}
    for cap in sorted(proto.evidence.loc[proto.evidence[ORIGINAL_LABEL] == benign, CAPTURE].unique()):
        pool = proto.training_pool(published, lab_names=labs)
        pool = pool[pool[CAPTURE] != cap]
        t0 = time.perf_counter()
        pre, model, thr = fold_fit(pool, feats, cand, cfg)
        hold = proto.evidence[proto.evidence[CAPTURE] == cap]
        pred, _ = predict_labels(pre, model, hold, feats, thr, benign)
        out["benign_loco"].append({"capture": cap, "flows": int(len(hold)), "threshold": thr,
                                   "false_positives": int((pred != benign).sum()),
                                   "fpr": float((pred != benign).mean()), "seconds": time.perf_counter() - t0})
        log.info("%s LOCO %s fpr=%.4f", cand["name"], cap, out["benign_loco"][-1]["fpr"])
    recon_label = cfg["experiments"]["recon_label"]
    for run in proto.recon_runs:
        others = [d for n, d in proto.recon_lab.items() if n != run] if use_runs else []
        pool = proto.training_pool(published, extra=others, lab_names=labs)
        if run.startswith("dataset:"):
            prefix = run.split(":", 1)[1]
            pool = pool[pool[CAPTURE].map(lambda c: not str(c).startswith(prefix))]
            held = proto.evidence[proto.evidence[CAPTURE].map(capture_prefix) == prefix]
        else:
            pool = pool[pool[RUN] != f"lab:{run}"]
            held = load_lab_set(run, cfg)
        if not (pool[LABEL] == recon_label).any():
            out["recon_loro"].append({"run": run, "skipped": "no other recon run left for training"})
            continue
        pre, model, thr = fold_fit(pool, feats, cand, cfg)
        pred, _ = predict_labels(pre, model, held, feats, thr, benign)
        y = held[LABEL].to_numpy()
        atk, ben = y == recon_label, y == benign
        out["recon_loro"].append({
            "run": run, "attack_flows": int(atk.sum()), "benign_flows": int(ben.sum()), "threshold": thr,
            "attack_recall": float((pred[atk] != benign).mean()) if atk.any() else None,
            "class_recall": float((pred[atk] == recon_label).mean()) if atk.any() else None,
            "benign_fpr": float((pred[ben] != benign).mean()) if ben.any() else None,
        })
        log.info("%s LORO %s %s", cand["name"], run, out["recon_loro"][-1])
    loco = [r["fpr"] for r in out["benign_loco"]]
    loro = [r["attack_recall"] for r in out["recon_loro"] if r.get("attack_recall") is not None]
    out["benign_loco_mean_fpr"] = float(np.mean(loco)) if loco else None
    out["benign_loco_max_fpr"] = float(np.max(loco)) if loco else None
    out["recon_loro_mean_recall"] = float(np.mean(loro)) if loro else None
    out["recon_loro_min_recall"] = float(np.min(loro)) if loro else None
    return out


def cfg_benign(cfg: dict[str, Any]) -> int:
    return cfg["benign_label"]


def lab_scores(predict, proto: Protocol) -> dict[str, Any]:
    """predict(frame) -> labels; scores every lab evaluation set."""
    benign = cfg_benign(proto.cfg)
    res = {}
    for name, lab in proto.lab_eval.items():
        pred = predict(lab)
        y = lab[LABEL].to_numpy()
        ben = y == benign
        r = {"flows": int(len(lab)), "benign_flows": int(ben.sum()), "attack_flows": int((~ben).sum()),
             "benign_fpr": float((pred[ben] != benign).mean()) if ben.any() else None}
        if (~ben).any():
            r["attack_recall"] = float((pred[~ben] != benign).mean())
            r["class_recall"] = float((pred[~ben] == y[~ben]).mean())
        res[name] = r
    return res


def score_existing(model_dir: Path, proto: Protocol) -> dict[str, Any]:
    """Score an already trained model on the evidence test set and lab sets (no retraining)."""
    names = class_names(proto.cfg)
    p = FlowPredictor(model_dir)

    def predict(frame: pd.DataFrame) -> np.ndarray:
        cols = [c for c in frame.columns if not c.startswith("_")]
        return p.predict_frame(frame[cols], source="dataset")["predicted_label"].to_numpy()

    y_pred = predict(proto.test)
    test = classification_metrics(proto.test[LABEL].to_numpy(), y_pred, proto.labels, names, proto.cfg["benign_label"])
    other = sorted(set(int(v) for v in y_pred) - set(proto.labels))
    test["predicted_outside_evidence_classes"] = {names[c]: int((y_pred == c).sum()) for c in other}
    return {"test": test, "lab": lab_scores(predict, proto)}


def run(cfg: dict[str, Any], only: list[str] | None, skip_grouped: bool, skip_features: bool) -> dict[str, Any]:
    ex = cfg["experiments"]
    started = time.perf_counter()
    proto = Protocol(cfg)
    models_dir = get_path("models_dir", cfg)
    out_dir = get_path("reports_dir", cfg)
    processed = get_path("processed_dir", cfg)
    processed.mkdir(parents=True, exist_ok=True)
    profile_csv = processed / "comparison_test_flows.csv"
    proto.test[[c for c in proto.test.columns if not c.startswith("_")]].to_csv(profile_csv, index=False)

    result_path = out_dir / "model_comparison.json"
    previous = json.loads(result_path.read_text()) if result_path.exists() and only else {}
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "protocol": {"labels": "evidence", "split": "temporal", "test_fraction": cfg["training"]["test_fraction"],
                     "test_rows": int(len(proto.test)),
                     "test_class_counts": {int(k): int(v) for k, v in proto.test[LABEL].value_counts().sort_index().items()},
                     "lab_train_sets": ex["lab_train_sets"], "lab_eval_sets": ex["lab_eval_sets"],
                     "recon_runs": proto.recon_runs, "threshold_tuning": cfg["training"]["threshold_tuning"],
                     "label_policy_report": proto.policy_report},
        "feature_analysis": previous.get("feature_analysis"),
        "baseline": previous.get("baseline"),
        "candidates": {c["name"]: c for c in previous.get("candidates", {}).values()} if previous else {},
    }

    if not skip_features and (not only or "features" in only):
        pool = proto.training_pool()
        report["feature_analysis"] = analyse(pool, proto.features, cfg, fit_model, class_names(cfg),
                                             _imbalance(ex["feature_analysis_imbalance"]), ex["feature_k_sweep"])
        log.info("feature analysis: selected k=%s", report["feature_analysis"]["selected_k"])
    selected = (report.get("feature_analysis") or {}).get("selected_features")

    if not only or "baseline" in only:
        bname = ex["baseline_model"]
        base = {"name": bname, "existing_model": True, **score_existing(models_dir / bname, proto)}
        reg = json.loads((models_dir / "registry.json").read_text()).get(bname, {})
        base["published_label_test"] = {k: reg.get(k) for k in ("accuracy", "f1_macro", "f1_weighted")}
        prev_metrics = json.loads((models_dir / bname / "metrics.json").read_text())["test"]
        base["published_label_test"].update(recall_macro=prev_metrics["recall_macro"],
                                            binary=prev_metrics["binary"])
        if not skip_grouped:
            recipe = {"name": bname, "model": "extratrees", "imbalance": None, "tune": False,
                      "lab_train_sets": ex["baseline_lab_train_sets"], "train_on_recon_runs": False}
            base["grouped"] = grouped(proto, recipe, published=True)
        base["profile"] = profile_in_subprocess(models_dir / bname, profile_csv)
        report["baseline"] = base
        _save(report, result_path)

    for cand in ex["candidates"]:
        if only and cand["name"] not in only:
            continue
        c = copy.deepcopy(cand)
        if c.get("features") == "selected":
            if not selected:
                raise ValueError(f"{c['name']} needs the feature analysis (run without --skip-features)")
            c["keep_features"] = selected
        full = dict(cfg["models"][c["model"]])
        full.update(c.get("params") or {})
        c["params_full"] = full
        log.info("training %s", c["name"])
        res = run_training(c["model"], "evidence", "temporal", c["name"], cfg=cfg, df=proto.raw,
                           benign_holdout=None, lab_train=ex["lab_train_sets"], lab_eval=ex["lab_eval_sets"],
                           imbalance=_imbalance(c.get("imbalance")), keep_features=c.get("keep_features"),
                           model_params=full, tune=c.get("tune", True))
        p = FlowPredictor(models_dir / c["name"])

        def predict(frame: pd.DataFrame, p=p) -> np.ndarray:
            cols = [k for k in frame.columns if not k.startswith("_")]
            return p.predict_frame(frame[cols], source="dataset")["predicted_label"].to_numpy()

        entry = {"name": c["name"], "model": c["model"], "imbalance": c.get("imbalance"),
                 "params": c.get("params"), "features": c.get("features", "all"),
                 "n_features": len(c["keep_features"]) if c.get("keep_features") else None,
                 "decision": res["decision"], "test": res["test"], "lab": lab_scores(predict, proto),
                 "imbalance_report": res["imbalance"], "fit_seconds": res["fit_seconds"],
                 "leakage_checks": res["leakage_checks"]}
        if not skip_grouped:
            entry["grouped"] = grouped(proto, c)
        entry["profile"] = profile_in_subprocess(models_dir / c["name"], profile_csv)
        report["candidates"][c["name"]] = entry
        _save(report, result_path)
        log.info("%s done: macroF1=%.4f", c["name"], res["test"]["f1_macro"])

    report["total_seconds"] = time.perf_counter() - started
    _save(report, result_path)
    return report


def reprofile(cfg: dict[str, Any]) -> None:
    path = get_path("reports_dir", cfg) / "model_comparison.json"
    report = json.loads(path.read_text())
    models_dir = get_path("models_dir", cfg)
    csv = get_path("processed_dir", cfg) / "comparison_test_flows.csv"
    for entry in [report["baseline"], *report["candidates"].values()]:
        entry["profile"] = profile_in_subprocess(models_dir / entry["name"], csv)
        log.info("profiled %s: %s", entry["name"], entry["profile"])
    report["profiled_at"] = datetime.now(timezone.utc).isoformat()
    _save(report, path)


def _save(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", help="candidate names (plus 'baseline', 'features') to (re)run")
    ap.add_argument("--skip-grouped", action="store_true", help="skip leave-one-out evaluations")
    ap.add_argument("--skip-features", action="store_true", help="skip the feature analysis")
    ap.add_argument("--reprofile", action="store_true",
                    help="only re-measure the resource profile of every compared model (on an idle machine)")
    args = ap.parse_args(argv)
    if args.reprofile:
        reprofile(load_config())
        return
    rep = run(load_config(), args.only, args.skip_grouped, args.skip_features)
    print(f"done in {rep['total_seconds']:.0f}s -> reports/model_comparison.json")


if __name__ == "__main__":
    main()
