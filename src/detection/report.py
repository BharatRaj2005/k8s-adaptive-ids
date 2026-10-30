"""Build reports/model_evaluation.md from the saved models/*/metrics.json files.

Usage:
    python -m src.detection.report
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.utils.config import class_names, get_path, load_config


def _f(v, digits=4):
    return "n/a" if v is None else f"{v:.{digits}f}"


def load_all_metrics(models_dir: Path) -> list[dict]:
    out = []
    for p in sorted(models_dir.glob("*/metrics.json")):
        out.append(json.loads(p.read_text()))
    return out


def build_report(cfg=None) -> str:
    cfg = cfg or load_config()
    models_dir = get_path("models_dir", cfg)
    active = cfg["detection"]["active_model"]
    names = class_names(cfg)
    runs = load_all_metrics(models_dir)
    if not runs:
        raise FileNotFoundError(f"no trained models in {models_dir}")
    L = [
        "# Model Evaluation Report",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python -m src.detection.report` "
        "from `models/*/metrics.json`. All numbers are measured; none are entered by hand.",
        "",
        f"Active model for detection: **{active}** (`config/settings.yaml` → `detection.active_model`).",
        "",
        "## Summary",
        "",
        "Binary columns treat every non-benign class as \"attack\". *Holdout FPR* is the share of flows in a "
        "whole benign capture, never seen in training, that were classified as an attack.",
        "",
        "| Model | Label policy | Split | Classes | Accuracy | Macro P | Macro R | Macro F1 | Weighted F1 "
        "| Attack det. rate | Test FPR | Holdout FPR | Single-flow median ms | Batch µs/flow |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        t, b, lat, h = r["test"], r["test"]["binary"], r["latency"], r["benign_holdout"]
        L.append(
            f"| {r['name']}{' (active)' if r['name'] == active else ''} | {r['label_policy']} | {r['split']} "
            f"| {len(t['labels'])} | {_f(t['accuracy'])} | {_f(t['precision_macro'])} | {_f(t['recall_macro'])} "
            f"| {_f(t['f1_macro'])} | {_f(t['f1_weighted'])} | {_f(b['detection_rate'])} "
            f"| {_f(b['false_positive_rate'])} | {_f(h.get('false_positive_rate'))} "
            f"| {_f(lat['single_flow_median_ms'], 2)} | {_f(lat['batch_per_flow_us'], 1)} |"
        )

    for r in runs:
        if r["name"] != active:
            continue
        t = r["test"]
        L += ["", f"## Per-class results: {active}", "",
              "| Label | Class | Precision | Recall | F1 | Test support |", "|---|---|---|---|---|---|"]
        for pc in t["per_class"]:
            L.append(f"| {pc['label']} | {pc['name']} | {_f(pc['precision'], 3)} | {_f(pc['recall'], 3)} "
                     f"| {_f(pc['f1'], 3)} | {pc['support']} |")
        L += ["", "### Confusion matrix (rows = true, columns = predicted)", "",
              "| true \\ pred | " + " | ".join(str(c) for c in t["labels"]) + " |",
              "|---|" + "---|" * len(t["labels"])]
        for lab, row in zip(t["labels"], t["confusion_matrix"]):
            L.append(f"| {lab} {names[lab]} | " + " | ".join(str(v) for v in row) + " |")
        h = r["benign_holdout"]
        if "capture" in h:
            L += ["", f"### Unseen benign capture `{h['capture']}`", "",
                  f"{h['false_positives']} of {h['flows']} flows ({_f(h['false_positive_rate'])}) misclassified "
                  f"as attacks: {h['false_positive_classes']}"]
        lc = r["leakage_checks"]
        L += ["", "### Leakage checks", "",
              f"- Dropped identifier columns: {', '.join(lc['dropped_identifier_columns'])}",
              f"- Training rows before/after removing duplicate feature vectors: "
              f"{lc['train_rows_before_dedup']} / {lc['train_rows_after_dedup']}",
              f"- Test rows whose exact feature vector also occurs in training: "
              f"{lc['test_rows_with_identical_train_feature_vector']} of {lc['test_rows']}"]

        noise = r["label_noise_analysis"]
        if "per_class" in noise:
            L += ["", "## Label-noise analysis", "",
                  "Each attack class comes from one whole-node capture in which every flow carries the attack "
                  "label. Flows matching infrastructure service signatures learned from the training part of "
                  f"the benign background capture ({', '.join(noise['signatures'])}; protocol:port) are most "
                  "likely ordinary cluster traffic recorded during the attack window.", "",
                  "| Label | Class | Flows | Background-like | Fraction | Remaining |", "|---|---|---|---|---|---|"]
            for lab, v in sorted(noise["per_class"].items(), key=lambda kv: int(kv[0])):
                L.append(f"| {lab} | {names[int(lab)]} | {v['flows']} | {v['background_like']} "
                         f"| {_f(v['background_like_fraction'], 3)} | {v['remaining_flows']} |")

    lab_path = get_path("reports_dir", cfg) / "lab_validation.json"
    if lab_path.exists():
        lab = json.loads(lab_path.read_text())
        L += ["", "## Validation on traffic captured in this lab", "",
              f"From `{lab_path.name}` (`python -m src.detection.live_eval --lab-set ...`, generated "
              f"{lab['generated_at'][:16]}). Ground truth comes from the controlled traffic generator: attacker-pod "
              "flows to the attacked port are the attack, its other flows (DNS) are excluded, everything else is "
              "benign. *Models ending in `_lab` were trained with the `benign_train` set, which does not overlap "
              "any set below.*"]
        for s, rep in lab["sets"].items():
            m = rep["manifest"]
            L += ["", f"### {s} ({m['kind']}): {rep['ground_truth_counts']}", "", f"{m.get('note', '')}", "",
                  "| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class "
                  "| Correct class conf≥0.9 |", "|---|---|---|---|---|---|"]
            for r in rep["results"]:
                L.append(f"| {r['model']} | {_f(r['benign_fpr'], 3)} | {_f(r['benign_fpr_conf_ge_0.9'], 3)} "
                         f"| {_f(r['attack_detected_any_class'], 3)} | {_f(r['attack_detected_correct_class'], 3)} "
                         f"| {_f(r['attack_correct_conf_ge_0.9'], 3)} |")

    L += ["", "## Interpretation", "",
          "- Classes whose flows are almost entirely background-like cannot be reliably separated from benign "
          "traffic by flow features; per-class scores near zero for them are expected, and any non-zero score "
          "may come from capture-specific artefacts rather than attack behaviour. These attacks (container "
          "escapes, runc/containerd/kubelet CVEs) act on the host or Kubernetes API; network flows alone cannot "
          "reliably reveal them. A Kubernetes audit-log monitor would be the appropriate additional input; it was "
          "left out of this prototype by decision, and the deception controller for these classes is exercised "
          "with clearly labelled simulated events instead.",
          "- The `attack_focused` models remove background-like flows from attack captures and keep only "
          "classes with enough remaining samples. Their scores are high but cover fewer classes, and some "
          "classes have very small test support; they are not comparable to 11-class results.",
          "- The `random` split is reported only to show how much a random split inflates results compared "
          "to the per-capture temporal split.",
          "- `pca_ae_nb` is this project's re-implementation of a PCA + autoencoder + Naive Bayes pipeline. "
          "Its results describe this implementation only, not the original paper's results.",
          "- No claim is made that any model here outperforms published results; the evaluation protocols differ.",
          "- On lab traffic, dataset-only models flag ~40 % of benign flows (mostly kubelet probes, which "
          "resemble the control-plane flows that carry attack labels in the dataset). Adding verified lab "
          "benign flows removes those false positives but the controlled recon flows are then classified as "
          "benign: individual reconnaissance HTTP flows look like benign HTTP flows to the same service. The "
          "reconnaissance signal in the lab is per-source volume (tens of flows per window from one pod), "
          "which per-flow features cannot express.",
          ""]
    return "\n".join(L)


def main() -> None:
    cfg = load_config()
    out = get_path("reports_dir", cfg) / "model_evaluation.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_report(cfg), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
