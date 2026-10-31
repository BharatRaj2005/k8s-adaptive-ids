# Model comparison

Generated from `reports/model_comparison.json` (`python -m src.detection.experiments`, run 2026-10-31T04:50:59Z; resource profiles re-measured on an idle machine 2026-10-31T05:22:00Z). Every candidate went through the same protocol.

## Protocol

1. **Labels.** Evidence-based per-flow labels (`reports/dataset_quality.md`). Ambiguous flows are excluded, and classes without enough attack evidence (1, 5, 7–10) are not trained. Trained classes: [0, 2, 3, 4, 6].
2. **Split.** Temporal: the latest 25% of every capture is the test set (16,149 flows; per class {'0': 15566, '2': 573, '3': 4, '4': 2, '6': 4}).
3. **Lab data.** ['benign_train', 'recon_run1'] join the training part only. Independent lab evaluation sets, never used for training or tuning: ['benign_eval_a', 'benign_eval_b', 'recon_run2'].
4. **Threshold.** A flow is malicious when 1 − P(benign) ≥ t. t is tuned on the latest 20% of each training capture, as the highest validation macro F1 with validation benign FPR ≤ 0.5%. The test set is never used. Plain argmax competes as well.
5. **Benign leave-one-capture-out (LOCO).** Retrain without one whole benign capture and measure false positives on it. The threshold is re-tuned inside each fold.
6. **Recon leave-one-run-out (LORO).** Over the independent recon executions ['dataset:reconnaissance', 'recon_run1', 'recon_run2']: retrain without the run and measure its recall. Only class 2 has more than one execution; every other attack class was executed once, so **no independent-run evaluation is possible for it**.
7. **Resources.** File size, RSS and peak RSS (VmHWM), batch and single-flow latency of the saved model, each measured in a fresh process on the same 16k test flows.
8. **Baseline.** The previously active `extratrees_dataset_lab`, scored on the same test rows and lab sets without retraining. Its LOCO/LORO folds retrain its own recipe: published labels, original parameters, lab benign data only.

## Results

| Model | Macro F1 | Macro recall | Macro precision | Accuracy | Weighted F1 | Benign FPR (test) | Attack recall (test) | Lab benign FPR | Lab recon recall (`recon_run2`) | LOCO mean FPR | Size MB | Peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline `extratrees_dataset_lab` | 0.399 | 0.480 | 0.392 | 0.9812 | 0.9869 | 1.59% | 90.4% | 0.00% | 0.0% | 20.0% | 466 | 1183 |
| `v2_et_balanced` | 0.595 | 0.597 | 0.643 | 0.9977 | 0.9976 | 0.14% | 97.9% | 0.28% | 99.0% | 19.1% | 53 | 389 |
| `v2_et_sqrt` | 0.596 | 0.598 | 0.644 | 0.9981 | 0.9980 | 0.12% | 98.3% | 0.14% | 99.0% | 19.1% | 45 | 370 |
| **`v2_et_none`** (selected) | 0.729 | 0.748 | 0.763 | 0.9982 | 0.9982 | 0.13% | 99.1% | 0.07% | 99.0% | 18.8% | 42 | 367 |
| `v2_et_smote` | 0.773 | 0.848 | 0.786 | 0.9969 | 0.9970 | 0.28% | 99.5% | 0.28% | 99.0% | 18.6% | 47 | 375 |
| `v2_et_under` | 0.535 | 0.548 | 0.525 | 0.9942 | 0.9944 | 0.53% | 99.5% | 0.76% | 99.5% | 19.5% | 34 | 351 |
| `v2_rf_balanced` | 0.553 | 0.548 | 0.568 | 0.9929 | 0.9931 | 0.68% | 99.1% | 1.72% | 100.0% | 8.2% | 10 | 307 |
| `v2_lgbm_balanced` | 0.691 | 0.687 | 0.696 | 0.9968 | 0.9967 | 0.06% | 93.0% | 0.00% | 98.5% | 19.1% | 6 | 293 |
| `v2_xgb_sqrt` | 0.696 | 0.695 | 0.696 | 0.9983 | 0.9981 | 0.06% | 97.1% | 0.07% | 99.0% | 19.1% | 2 | 302 |
| `v2_et_sqrt_selected` | 0.503 | 0.450 | 0.595 | 0.9902 | 0.9894 | 0.05% | 74.3% | 0.41% | 94.1% | 18.2% | 28 | 337 |
| `v2_et_sqrt_small` | 0.588 | 0.598 | 0.629 | 0.9952 | 0.9952 | 0.43% | 98.6% | 0.28% | 99.5% | 19.0% | 12 | 310 |

Macro metrics average the five trained classes. Benign FPR is the share of benign test flows flagged as any attack, and attack recall is the share of attack flows flagged as any attack.

### The baseline on its own published-label test set

On the original labels the baseline reported accuracy 0.9655, macro F1 0.2791, macro recall 0.2562 and weighted F1 0.9602. That test set counts cluster background as attacks (see the dataset report), so those numbers are not comparable with the table above. In the table the baseline is scored on the evidence labels like every candidate. It still predicts the untrained classes for 140 test flows ({'CVE-2020-13379': 13, 'CVE-2021-43798': 6, 'CVE-2021-30465': 8, 'CVE-2021-25741': 89, 'CVE-2022-23648': 15, 'CVE-2019-5736': 9}), and each of those counts as an error.

## Per-class results (test set)

| Model | Benign F1 (n=15566) | Node-RED Reconnaissance F1 (n=573) | Node-RED RCE F1 (n=4) | Node-RED Container Escape F1 (n=2) | CVE-2019-20933 F1 (n=4) |
|---|---|---|---|---|---|
| `extratrees_dataset_lab` | 0.99 | 0.91 | 0.00 | 0.00 | 0.09 |
| `v2_et_balanced` | 1.00 | 0.97 | 0.00 | 0.33 | 0.67 |
| `v2_et_sqrt` | 1.00 | 0.98 | 0.00 | 0.33 | 0.67 |
| `v2_et_none` | 1.00 | 0.98 | 0.67 | 0.33 | 0.67 |
| `v2_et_smote` | 1.00 | 0.96 | 0.67 | 0.57 | 0.67 |
| `v2_et_under` | 1.00 | 0.93 | 0.25 | 0.00 | 0.50 |
| `v2_rf_balanced` | 1.00 | 0.91 | 0.00 | 0.00 | 0.86 |
| `v2_lgbm_balanced` | 1.00 | 0.96 | 0.00 | 0.50 | 1.00 |
| `v2_xgb_sqrt` | 1.00 | 0.98 | 0.00 | 0.50 | 1.00 |
| `v2_et_sqrt_selected` | 0.99 | 0.85 | 0.00 | 0.00 | 0.67 |
| `v2_et_sqrt_small` | 1.00 | 0.94 | 0.00 | 0.33 | 0.67 |

Recall 95% Wilson intervals for the selected model: Benign 1.00 [1.00, 1.00]; Node-RED Reconnaissance 0.99 [0.98, 1.00]; Node-RED RCE 0.75 [0.30, 0.95]; Node-RED Container Escape 0.50 [0.09, 0.91]; CVE-2019-20933 0.50 [0.15, 0.85].

**Classes 3, 4 and 6 have 4, 2 and 4 test flows.** One flow more or less moves their F1 by 0.2–0.5, and the intervals above span most of [0, 1]. Differences in macro F1 between candidates are therefore mostly driven by one or two flows and are not statistically meaningful. The reliable comparisons are the benign and recon results, which rest on thousands of flows.

### Confusion matrix of the selected model (rows: true, columns: predicted)

| true \ predicted | Benign | Node-RED Reconnaissance | Node-RED RCE | Node-RED Container Escape | CVE-2019-20933 |
|---|---|---|---|---|---|
| Benign | 15546 | 19 | 0 | 1 | 0 |
| Node-RED Reconnaissance | 5 | 568 | 0 | 0 | 0 |
| Node-RED RCE | 0 | 0 | 3 | 1 | 0 |
| Node-RED Container Escape | 0 | 0 | 1 | 1 | 0 |
| CVE-2019-20933 | 0 | 0 | 1 | 1 | 2 |

## Grouped validation

| Model | LOCO FPR per held-out benign capture | LORO recall per held-out recon run |
|---|---|---|
| `extratrees_dataset_lab` | background 2.4%, grafana 0.7%, grafana 0.4%, nodered 76.7% | dataset reconnaissance skipped, recon_run1 0.0%, recon_run2 0.0% |
| `v2_et_balanced` | background 0.0%, grafana 0.2%, grafana 0.0%, nodered 76.2% | dataset reconnaissance 0.0%, recon_run1 98.3%, recon_run2 99.0% |
| `v2_et_sqrt` | background 0.0%, grafana 0.7%, grafana 0.0%, nodered 75.6% | dataset reconnaissance 0.0%, recon_run1 99.0%, recon_run2 99.0% |
| `v2_et_none` | background 0.0%, grafana 1.0%, grafana 0.1%, nodered 74.0% | dataset reconnaissance 0.0%, recon_run1 99.7%, recon_run2 99.0% |
| `v2_et_smote` | background 0.0%, grafana 0.2%, grafana 0.0%, nodered 74.3% | dataset reconnaissance 0.0%, recon_run1 98.3%, recon_run2 99.0% |
| `v2_et_under` | background 0.0%, grafana 1.6%, grafana 0.1%, nodered 76.3% | dataset reconnaissance 0.0%, recon_run1 99.3%, recon_run2 99.5% |
| `v2_rf_balanced` | background 0.0%, grafana 0.7%, grafana 0.1%, nodered 32.1% | dataset reconnaissance 0.0%, recon_run1 99.3%, recon_run2 100.0% |
| `v2_lgbm_balanced` | background 0.0%, grafana 0.0%, grafana 0.0%, nodered 76.3% | dataset reconnaissance 0.0%, recon_run1 98.7%, recon_run2 98.5% |
| `v2_xgb_sqrt` | background 0.0%, grafana 0.0%, grafana 0.0%, nodered 76.3% | dataset reconnaissance 0.0%, recon_run1 98.3%, recon_run2 99.0% |
| `v2_et_sqrt_selected` | background 0.0%, grafana 0.0%, grafana 0.0%, nodered 72.9% | dataset reconnaissance 0.0%, recon_run1 90.8%, recon_run2 94.1% |
| `v2_et_sqrt_small` | background 0.0%, grafana 0.1%, grafana 0.0%, nodered 75.8% | dataset reconnaissance 0.0%, recon_run1 99.0%, recon_run2 99.5% |

Findings:

* **Unseen benign application.** When the whole Node-RED benign capture is held out, every model flags most of that capture (≈ 73–77%; Random Forest 32%). The only other traffic on :1880 is reconnaissance, so without benign Node-RED examples, any Node-RED traffic looks like recon. A newly deployed application therefore needs benign examples (as the lab benign sets provide) before the per-flow classifier can be trusted on it. The behavioural detector does not have this dependency.
* **Recon across environments.** No model trained without the dataset's recon capture recognises it from the lab recon runs alone (0% LORO recall), and the baseline, trained without lab recon, recognises no lab run (0%). Within one environment, held-out lab runs are detected at ≈ 91–100%. The per-flow classifier learns how this lab's scanner looks, not reconnaissance in general.

## Feature analysis

Computed on a validation split of the training data (10,214 flows, 435 attack flows) with an ExtraTrees reference model. 58 features remain after the constant/correlation filter (5 constant, 17 correlated above |r| > 0.99).

Top features by permutation importance (macro F1 drop) with mutual information:

| Feature | Permutation importance | Mutual information |
|---|---|---|
| Dst Port | 0.1019 ± 0.0616 | 0.0730 |
| Bwd Init Win Bytes | 0.0223 ± 0.0163 | 0.0398 |
| FIN Flag Count | 0.0091 ± 0.0158 | 0.0148 |
| Fwd Packet Length Max | 0.0072 ± 0.0003 | 0.1681 |
| Fwd Packet Length Std | 0.0064 ± 0.0004 | 0.1819 |
| Total Length of Fwd Packet | 0.0063 ± 0.0005 | 0.1616 |
| Fwd Packet Length Mean | 0.0051 ± 0.0004 | 0.1590 |
| Subflow Fwd Bytes | 0.0044 ± 0.0009 | 0.1006 |
| Fwd Packets/s | 0.0035 ± 0.0007 | 0.0249 |
| Down/Up Ratio | 0.0030 ± 0.0006 | 0.0374 |
| Bwd Packets/s | 0.0020 ± 0.0002 | 0.0349 |
| Flow Packets/s | 0.0018 ± 0.0009 | 0.0231 |
| Total Fwd Packet | 0.0012 ± 0.0004 | 0.0345 |
| Bwd PSH Flags | 0.0011 ± 0.0007 | 0.0340 |
| Fwd IAT Std | 0.0010 ± 0.0004 | 0.0384 |

Most informative features per attack class (one-vs-rest mutual information):

* **Node-RED Reconnaissance**: Total Length of Bwd Packet, Bwd Packet Length Std, Bwd Packet Length Mean, Bwd Packet Length Max, Packet Length Std
* **Node-RED RCE**: Fwd Seg Size Min, Protocol, SYN Flag Count, FIN Flag Count, Fwd Packet Length Max
* **Node-RED Container Escape**: Fwd Seg Size Min, Protocol, FIN Flag Count, SYN Flag Count, Down/Up Ratio
* **CVE-2019-20933**: Fwd Seg Size Min, Protocol, FIN Flag Count, Dst Port, SYN Flag Count

Top-k sweep (validation; a stand-in for recursive elimination):

| k | Macro F1 | Benign FPR | Attack recall |
|---|---|---|---|
| 8 | 0.594 | 0.16% | 98.9% |
| 12 | 0.592 | 0.24% | 97.9% |
| 16 | 0.593 | 0.14% | 96.6% |
| 24 | 0.597 | 0.04% | 98.4% |
| 32 | 0.596 | 0.04% | 97.5% |
| 48 | 0.594 | 0.04% | 95.4% |
| 58 | 0.585 | 0.02% | 86.7% |

On validation, every k scored within 0.01 macro F1, and the rule picked k = 8. On the test set, however, that subset lost attack recall (74.3% vs 98.3% with all features). The validation split has too few minority-class flows to rank subsets, so **all features are kept**. SHAP was not used, to avoid a new dependency; permutation importance covers the same question for these models.

Recon differs from benign Node-RED traffic mainly in response sizes (Bwd packet lengths): most probed paths return small error pages. The few RCE, escape and InfluxDB flows are separated by TCP-level properties (Fwd Seg Size Min, SYN/FIN flags, protocol, destination port) rather than by content.

## Selection

**Selected: `v2_et_none`.** ExtraTrees, 300 trees, no class weighting, attack threshold 0.3 tuned on validation. Reasons:

* **Against the baseline**, on the same test rows: macro F1 0.399 → 0.729, macro recall 0.480 → 0.748, benign FPR 1.59% → 0.13%, attack recall 90.4% → 99.1%. On the held-out lab recon run, recall goes from 0.0% to 99.0%. Model size 466 → 42 MB, and peak RSS 1183 → 367 MB.
* **Among the candidates**:
  * `v2_et_smote` has the highest macro F1, but the gain comes from one or two flows of classes 3 and 4, at about twice the benign FPR.
  * `v2_xgb_sqrt` and `v2_lgbm_balanced` are much smaller (2–6 MB) with a slightly lower benign FPR, but they miss more attack flows on the test set (attack recall 97.1% and 93.0%).
  * `v2_rf_balanced` handles the unseen Node-RED capture best, but has 1–3% false positives on the lab benign sets, which would reach the deception controller.
  * Class weighting (`balanced`, `sqrt`) and undersampling did not help; SMOTE helped only within noise.
* **Lab benign FPR** of the selected model: 0.00% and 0.07% (1 of 1,450 flows), against 0 for the baseline. The controller acts on a single flow only at confidence ≥ 0.9 and otherwise needs repeated evidence.
* `v2_xgb_sqrt` is the recommended alternative where memory matters most.

The baseline model files are kept unchanged (`models/extratrees_dataset_lab`), and switching back is one line in `config/settings.yaml` (`detection.active_model`).
