"""Leave-one-application-out evaluation of unknown-traffic handling.

    python -m src.detection.loao_eval        # writes reports/unknown_traffic.{json,md}

For each application in `unknown_eval.applications` (plus a fold that holds out
nothing), all benign flows of that application's service ports are removed from
training: dataset captures and lab sets alike. Attack flows stay, as known attack
patterns. The model is the selected recipe (ExtraTrees, no class weighting,
validation-tuned threshold). Every threshold, including the decision threshold
and the novelty quantile, is calibrated on validation data drawn from the
training pool, which never contains the held-out application.

Scored per fold:
  held-out application benign flows -> false-positive rate, unknown rate
  benign flows of known applications -> false-positive rate, unknown rate (cost)
  attack flows (test split + held-out lab recon run) -> detected, unknown, missed
for each unknown-handling variant: none, each single check, all checks.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from src.detection.experiments import Protocol
from src.detection.models import decide, predict_proba
from src.detection.train import fit_model, tune_threshold
from src.detection.unknown import UNKNOWN, NoveltyScorer, assess, benign_service_profile, service_keys
from src.detection.evaluate import wilson_interval
from src.preprocessing.schema import LABEL
from src.preprocessing.splitting import TEST, TRAIN, temporal_split
from src.utils.config import get_path, load_config
from src.utils.logging_setup import get_logger

log = get_logger(__name__)
VARIANTS = {"none": [], "low_confidence": ["low_confidence"], "out_of_distribution": ["out_of_distribution"],
            "unfamiliar_service": ["unfamiliar_service"],
            "all": ["unfamiliar_service", "low_confidence", "out_of_distribution"]}


def _rate(n: int, d: int) -> dict[str, Any]:
    return {"n": int(n), "of": int(d), "rate": n / d if d else None, "ci95": wilson_interval(int(n), int(d))}


def _benign(frame: pd.DataFrame, cfg: dict[str, Any]) -> pd.DataFrame:
    return frame[frame[LABEL] == cfg["benign_label"]]


def run_fold(proto: Protocol, app: str | None, ports: list[int], cfg: dict[str, Any]) -> dict[str, Any]:
    benign, feats = cfg["benign_label"], proto.features
    ucfg = cfg["detection"]["unknown"]
    ecfg = cfg["unknown_eval"]
    svc_ports = {f"6:{p}" for p in ports} | {f"17:{p}" for p in ports}

    pool = proto.training_pool()
    on_app = service_keys(pool).isin(svc_ports).to_numpy() & (pool[LABEL] == benign).to_numpy()
    removed = pool[on_app]
    pool = pool[~on_app]

    t0 = time.perf_counter()
    thr = tune_threshold(pool, feats, "extratrees", cfg, {"strategy": "none"})["attack_threshold"]
    pre, model = fit_model(pool, feats, "extratrees", cfg, {"strategy": "none"})
    split = temporal_split(pool, cfg["training"]["threshold_tuning"]["val_fraction"])
    inner, val = pool[split == TRAIN], pool[split == TEST]
    scorer = NoveltyScorer(ecfg["novelty_k"], ecfg["novelty_sample"], cfg["training"]["random_state"])
    scorer.fit(pre.transform(inner[feats]), inner[LABEL].to_numpy(), benign)
    nov_thr = scorer.calibrate(pre.transform(val[feats]), ucfg["novelty_quantile"])
    profile = benign_service_profile(pool, benign)
    fit_s = time.perf_counter() - t0

    lab_benign = pd.concat([_benign(d, cfg) for n, d in proto.lab_eval.items()], ignore_index=True)
    test_benign = pd.concat([_benign(proto.test, cfg), lab_benign], ignore_index=True)
    test_app = service_keys(test_benign).isin(svc_ports).to_numpy()
    held_out = pd.concat([removed, test_benign[test_app]], ignore_index=True) if app else removed.iloc[0:0]
    known = test_benign[~test_app] if app else test_benign
    attacks = pd.concat([proto.test[proto.test[LABEL] != benign],
                         *(d[d[LABEL] != benign] for d in proto.lab_eval.values())], ignore_index=True)

    def verdicts(frame: pd.DataFrame) -> dict[str, np.ndarray]:
        if frame.empty:
            return {v: np.array([], dtype=object) for v in VARIANTS}
        X = pre.transform(frame[feats])
        labels, conf = decide(predict_proba(model, X), model.classes_, benign, thr)
        nov = scorer.score(X)
        svc = service_keys(frame).reset_index(drop=True)
        out = {}
        for v, checks in VARIANTS.items():
            st, _ = assess(labels, conf, svc, benign, {**ucfg, "checks": checks}, profile, nov, nov_thr)
            out[v] = st
        out["_labels"] = labels
        return out

    t1 = time.perf_counter()
    vh, vk, va = verdicts(held_out), verdicts(known), verdicts(attacks)
    per_flow_us = (time.perf_counter() - t1) / max(len(held_out) + len(known) + len(attacks), 1) * 1e6
    y_att = attacks[LABEL].to_numpy()
    att_on_app = service_keys(attacks).isin(svc_ports).to_numpy()

    res: dict[str, Any] = {"application": app or "(none held out)", "ports": ports, "threshold": thr,
                           "novelty_threshold": nov_thr, "held_out_training_flows_removed": int(len(removed)),
                           "fit_seconds": round(fit_s, 1), "inference_us_per_flow": round(per_flow_us, 1),
                           "services_with_benign_profile": len([k for k, v in profile.items()
                                                                if v >= ucfg["min_benign_service_flows"]]),
                           "variants": {}}
    for v in VARIANTS:
        r: dict[str, Any] = {}
        for name, st in (("held_out_app_benign", vh[v]), ("known_app_benign", vk[v])):
            d = len(st)
            r[name] = {"flows": d, "false_positive": _rate((st == "attack").sum(), d),
                       "unknown": _rate((st == UNKNOWN).sum(), d), "benign": _rate((st == "benign").sum(), d)}
        st = va[v]
        correct = st == "attack"
        r["attacks"] = {"flows": int(len(st)), "detected": _rate(correct.sum(), len(st)),
                        "unknown": _rate((st == UNKNOWN).sum(), len(st)),
                        "missed": _rate((st == "benign").sum(), len(st)),
                        "correct_class": _rate(((va["_labels"] == y_att) & correct).sum(), len(st)),
                        "on_held_out_app": {"flows": int(att_on_app.sum()),
                                            "detected": _rate((correct & att_on_app).sum(), att_on_app.sum()),
                                            "unknown": _rate(((st == UNKNOWN) & att_on_app).sum(), att_on_app.sum())}}
        fp = int((vh[v] == "attack").sum() + (vk[v] == "attack").sum())
        tp = int(correct.sum())
        r["attack_precision"] = tp / (tp + fp) if tp + fp else None
        r["attack_recall"] = tp / len(st) if len(st) else None
        res["variants"][v] = r
    log.info("LOAO %s: none FPR=%s all FPR=%s unknown=%s", app, res["variants"]["none"]["held_out_app_benign"]
             ["false_positive"]["rate"], res["variants"]["all"]["held_out_app_benign"]["false_positive"]["rate"],
             res["variants"]["all"]["held_out_app_benign"]["unknown"]["rate"])
    return res


def main() -> None:
    cfg = load_config()
    proto = Protocol(cfg)
    folds = [run_fold(proto, None, [], cfg)]
    for app, ports in cfg["unknown_eval"]["applications"].items():
        folds.append(run_fold(proto, app, ports, cfg))
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "unknown_config": cfg["detection"]["unknown"],
           "eval_config": cfg["unknown_eval"], "folds": folds}
    path = get_path("reports_dir", cfg) / "unknown_traffic.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    from src.detection.unknown_report import render

    path.with_suffix(".md").write_text(render(out, cfg["detection"]["unknown"]))
    print("wrote", path, "and", path.with_suffix(".md"))


if __name__ == "__main__":
    main()
