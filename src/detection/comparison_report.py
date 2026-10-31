"""Render reports/model_comparison.md from reports/model_comparison.json.

    python -m src.detection.comparison_report
"""
from __future__ import annotations

import json
from typing import Any

from src.utils.config import get_path, load_config


def _p(v: float | None, digits: int = 2) -> str:
    return "–" if v is None else f"{100 * v:.{digits}f}%"


def _n(v: float | None, digits: int = 3) -> str:
    return "–" if v is None else f"{v:.{digits}f}"


def _row(name: str, e: dict[str, Any], label: str) -> str:
    t, g, pr, lab = e["test"], e.get("grouped", {}), e.get("profile", {}), e.get("lab", {})
    return (f"| {label} | {_n(t['f1_macro'])} | {_n(t['recall_macro'])} | {_n(t['precision_macro'])} | "
            f"{t['accuracy']:.4f} | {t['f1_weighted']:.4f} | {_p(t['binary']['false_positive_rate'])} | "
            f"{_p(t['binary']['detection_rate'], 1)} | {_p(lab.get('benign_eval_b', {}).get('benign_fpr'))} | "
            f"{_p(lab.get('recon_run2', {}).get('attack_recall'), 1)} | {_p(g.get('benign_loco_mean_fpr'), 1)} | "
            f"{pr.get('model_bytes', 0) / 1e6:.0f} | {pr.get('peak_rss_mb', 0):.0f} |")


def render(r: dict[str, Any], selected: str) -> str:
    p = r["protocol"]
    base = r["baseline"]
    cands = r["candidates"]
    sel = cands[selected]
    names = {e: e for e in cands}
    L = ["# Model comparison", "",
         f"Generated from `reports/model_comparison.json` (`python -m src.detection.experiments`, run "
         f"{r['generated_at'][:19]}Z; resource profiles re-measured on an idle machine "
         f"{(r.get('profiled_at') or '')[:19]}Z). Every candidate went through the same protocol.", "",
         "## Protocol", "",
         "1. **Labels.** Evidence-based per-flow labels (`reports/dataset_quality.md`). Ambiguous flows are excluded, "
         "and classes without enough attack evidence (1, 5, 7–10) are not trained. Trained classes: "
         f"{sorted(int(k) for k in p['test_class_counts'])}.",
         f"2. **Split.** Temporal: the latest {p['test_fraction']:.0%} of every capture is the test set "
         f"({p['test_rows']:,} flows; per class {p['test_class_counts']}).",
         f"3. **Lab data.** {p['lab_train_sets']} join the training part only. Independent lab evaluation sets, "
         f"never used for training or tuning: {p['lab_eval_sets']}.",
         f"4. **Threshold.** A flow is malicious when 1 − P(benign) ≥ t. t is tuned on the latest "
         f"{p['threshold_tuning']['val_fraction']:.0%} of each training capture, as the highest validation macro F1 "
         f"with validation benign FPR ≤ {p['threshold_tuning']['max_val_benign_fpr']:.1%}. The test set is never used. "
         "Plain argmax competes as well.",
         "5. **Benign leave-one-capture-out (LOCO).** Retrain without one whole benign capture and measure false "
         "positives on it. The threshold is re-tuned inside each fold.",
         f"6. **Recon leave-one-run-out (LORO).** Over the independent recon executions {p['recon_runs']}: retrain "
         "without the run and measure its recall. Only class 2 has more than one execution; every other attack class "
         "was executed once, so **no independent-run evaluation is possible for it**.",
         "7. **Resources.** File size, RSS and peak RSS (VmHWM), batch and single-flow latency of the saved model, "
         "each measured in a fresh process on the same 16k test flows.",
         "8. **Baseline.** The previously active `extratrees_dataset_lab`, scored on the same test rows and lab sets "
         "without retraining. Its LOCO/LORO folds retrain its own recipe: published labels, original parameters, "
         "lab benign data only.", "",
         "## Results", "",
         "| Model | Macro F1 | Macro recall | Macro precision | Accuracy | Weighted F1 | Benign FPR (test) | "
         "Attack recall (test) | Lab benign FPR | Lab recon recall (`recon_run2`) | LOCO mean FPR | Size MB | Peak RSS MB |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
         _row(base["name"], base, f"baseline `{base['name']}`")]
    for n, e in cands.items():
        label = f"**`{n}`** (selected)" if n == selected else f"`{n}`"
        L.append(_row(n, e, label))
    L += ["", "Macro metrics average the five trained classes. Benign FPR is the share of benign test flows flagged "
          "as any attack, and attack recall is the share of attack flows flagged as any attack.", "",
          "### The baseline on its own published-label test set", "",
          f"On the original labels the baseline reported accuracy {base['published_label_test']['accuracy']:.4f}, "
          f"macro F1 {base['published_label_test']['f1_macro']:.4f}, macro recall "
          f"{base['published_label_test']['recall_macro']:.4f} and weighted F1 "
          f"{base['published_label_test']['f1_weighted']:.4f}. That test set counts cluster background as attacks "
          "(see the dataset report), so those numbers are not comparable with the table above. In the table the "
          "baseline is scored on the evidence labels like every candidate. It still predicts the untrained classes "
          f"for {sum(base['test']['predicted_outside_evidence_classes'].values())} test flows "
          f"({base['test']['predicted_outside_evidence_classes']}), and each of those counts as an error.", "",
          "## Per-class results (test set)", "",
          "| Model | " + " | ".join(f"{pc['name']} F1 (n={pc['support']})" for pc in base["test"]["per_class"]) + " |",
          "|---|" + "---|" * len(base["test"]["per_class"])]
    for n, e in [(base["name"], base), *cands.items()]:
        L.append(f"| `{n}` | " + " | ".join(f"{pc['f1']:.2f}" for pc in e["test"]["per_class"]) + " |")
    L += ["", f"Recall 95% Wilson intervals for the selected model: " + "; ".join(
        f"{pc['name']} {pc['recall']:.2f} [{pc['recall_ci95'][0]:.2f}, {pc['recall_ci95'][1]:.2f}]"
        for pc in sel["test"]["per_class"]) + ".", "",
          "**Classes 3, 4 and 6 have 4, 2 and 4 test flows.** One flow more or less moves their F1 by 0.2–0.5, and the "
          "intervals above span most of [0, 1]. Differences in macro F1 between candidates are therefore mostly "
          "driven by one or two flows and are not statistically meaningful. The reliable comparisons are the "
          "benign and recon results, which rest on thousands of flows.", "",
          "### Confusion matrix of the selected model (rows: true, columns: predicted)", ""]
    labels = sel["test"]["labels"]
    nm = {pc["label"]: pc["name"] for pc in sel["test"]["per_class"]}
    L += ["| true \\ predicted | " + " | ".join(nm[c] for c in labels) + " |", "|---|" + "---|" * len(labels)]
    for c, row in zip(labels, sel["test"]["confusion_matrix"]):
        L.append(f"| {nm[c]} | " + " | ".join(str(v) for v in row) + " |")
    L += ["", "## Grouped validation", "",
          "| Model | LOCO FPR per held-out benign capture | LORO recall per held-out recon run |", "|---|---|---|"]
    for n, e in [(base["name"], base), *cands.items()]:
        g = e.get("grouped", {})
        loco = ", ".join(f"{x['capture'].split('_')[0]} {_p(x['fpr'], 1)}" for x in g.get("benign_loco", []))
        loro = ", ".join(f"{x['run'].replace('dataset:', 'dataset ')} "
                         f"{'skipped' if 'skipped' in x else _p(x.get('attack_recall'), 1)}" for x in g.get("recon_loro", []))
        L.append(f"| `{n}` | {loco} | {loro} |")
    L += ["", "Findings:", "",
          "* **Unseen benign application.** When the whole Node-RED benign capture is held out, every model flags "
          "most of that capture (≈ 73–77%; Random Forest 32%). The only other traffic on :1880 is reconnaissance, so "
          "without benign Node-RED examples, any Node-RED traffic looks like recon. A newly deployed application "
          "therefore needs benign examples (as the lab benign sets provide) before the per-flow classifier can be "
          "trusted on it. The behavioural detector does not have this dependency.",
          "* **Recon across environments.** No model trained without the dataset's recon capture recognises it from "
          "the lab recon runs alone (0% LORO recall), and the baseline, trained without lab recon, recognises no lab "
          "run (0%). Within one environment, held-out lab runs are detected at ≈ 91–100%. The per-flow classifier "
          "learns how this lab's scanner looks, not reconnaissance in general.", "",
          "## Feature analysis", ""]
    fa = r["feature_analysis"]
    L += [f"Computed on a validation split of the training data ({fa['validation_rows']:,} flows, "
          f"{fa['validation_attack_rows']} attack flows) with an ExtraTrees reference model. "
          f"{fa['features_after_cleaning']} features remain after the constant/correlation filter "
          f"({len(fa['dropped_constant'])} constant, {len(fa['dropped_correlated'])} correlated above |r| > 0.99).", "",
          "Top features by permutation importance (macro F1 drop) with mutual information:", "",
          "| Feature | Permutation importance | Mutual information |", "|---|---|---|"]
    for x in fa["ranking"][:15]:
        L.append(f"| {x['feature']} | {x['permutation_mean']:.4f} ± {x['permutation_std']:.4f} | {x['mutual_information']:.4f} |")
    L += ["", "Most informative features per attack class (one-vs-rest mutual information):", ""]
    for cls, feats in fa["per_class_mutual_information"].items():
        L.append(f"* **{cls}**: " + ", ".join(f[0] for f in feats[:5]))
    L += ["", "Top-k sweep (validation; a stand-in for recursive elimination):", "",
          "| k | Macro F1 | Benign FPR | Attack recall |", "|---|---|---|---|"]
    for s in fa["sweep"]:
        L.append(f"| {s['k']} | {s['f1_macro']:.3f} | {_p(s['benign_fpr'])} | {_p(s['attack_recall'], 1)} |")
    sf = cands.get("v2_et_sqrt_selected")
    L += ["", f"On validation, every k scored within {fa['tolerance']} macro F1, and the rule picked k = {fa['selected_k']}. "
          + (f"On the test set, however, that subset lost attack recall ({_p(sf['test']['binary']['detection_rate'], 1)} "
             f"vs {_p(cands['v2_et_sqrt']['test']['binary']['detection_rate'], 1)} with all features). The validation "
             "split has too few minority-class flows to rank subsets, so **all features are kept**. SHAP was not "
             "used, to avoid a new dependency; permutation importance covers the same question for these models."
             if sf else ""), "",
          "Recon differs from benign Node-RED traffic mainly in response sizes (Bwd packet lengths): most probed "
          "paths return small error pages. The few RCE, escape and InfluxDB flows are separated by TCP-level "
          "properties (Fwd Seg Size Min, SYN/FIN flags, protocol, destination port) rather than by content.", "",
          "## Selection", ""]
    s_t, b_t = sel["test"], base["test"]
    L += [f"**Selected: `{selected}`.** ExtraTrees, 300 trees, no class weighting, attack threshold "
          f"{sel['decision']['attack_threshold']} tuned on validation. Reasons:", "",
          f"* **Against the baseline**, on the same test rows: macro F1 {b_t['f1_macro']:.3f} → {s_t['f1_macro']:.3f}, "
          f"macro recall {b_t['recall_macro']:.3f} → {s_t['recall_macro']:.3f}, benign FPR "
          f"{_p(b_t['binary']['false_positive_rate'])} → {_p(s_t['binary']['false_positive_rate'])}, attack recall "
          f"{_p(b_t['binary']['detection_rate'], 1)} → {_p(s_t['binary']['detection_rate'], 1)}. On the held-out lab "
          f"recon run, recall goes from {_p(base['lab']['recon_run2'].get('attack_recall'), 1)} to "
          f"{_p(sel['lab']['recon_run2'].get('attack_recall'), 1)}. Model size {base['profile']['model_bytes'] / 1e6:.0f} → "
          f"{sel['profile']['model_bytes'] / 1e6:.0f} MB, and peak RSS {base['profile']['peak_rss_mb']:.0f} → "
          f"{sel['profile']['peak_rss_mb']:.0f} MB.",
          "* **Among the candidates**:",
          "  * `v2_et_smote` has the highest macro F1, but the gain comes from one or two flows of classes 3 and 4, at "
          "about twice the benign FPR.",
          "  * `v2_xgb_sqrt` and `v2_lgbm_balanced` are much smaller (2–6 MB) with a slightly lower benign FPR, but "
          "they miss more attack flows on the test set (attack recall 97.1% and 93.0%).",
          "  * `v2_rf_balanced` handles the unseen Node-RED capture best, but has 1–3% false positives on the lab "
          "benign sets, which would reach the deception controller.",
          "  * Class weighting (`balanced`, `sqrt`) and undersampling did not help; SMOTE helped only within noise.",
          f"* **Lab benign FPR** of the selected model: {_p(sel['lab']['benign_eval_a']['benign_fpr'])} and "
          f"{_p(sel['lab']['benign_eval_b']['benign_fpr'])} (1 of 1,450 flows), against 0 for the baseline. The "
          "controller acts on a single flow only at confidence ≥ 0.9 and otherwise needs repeated evidence.",
          "* `v2_xgb_sqrt` is the recommended alternative where memory matters most.", "",
          f"The baseline model files are kept unchanged (`models/{base['name']}`), and switching back is one line in "
          "`config/settings.yaml` (`detection.active_model`).", ""]
    return "\n".join(L)


def main() -> None:
    cfg = load_config()
    path = get_path("reports_dir", cfg) / "model_comparison.json"
    r = json.loads(path.read_text())
    selected = cfg["experiments"].get("selected_model") or cfg["detection"]["active_model"]
    if selected not in r["candidates"]:
        raise SystemExit(f"selected model {selected} is not among the compared candidates")
    path.with_suffix(".md").write_text(render(r, selected))
    print("wrote", path.with_suffix(".md"))


if __name__ == "__main__":
    main()
