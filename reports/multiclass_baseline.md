# Published-label 11-class baseline

Trained 2026-11-01 on the yigitsever/kubernetes-dataset published labels (every row in a
capture carries that capture's attack label), all 11 classes preserved. ExtraTrees (300 trees),
temporal split, config class weighting. Reproduced as `models/et_dataset_baseline`
(identical to the existing `models/extratrees_dataset`). Two imbalance variants trained for
comparison: `et_dataset_sqrt`, `et_dataset_smote`.

## Headline

| Model | Accuracy | Macro-F1 | Weighted-F1 | Benign holdout FPR |
|---|---|---|---|---|
| baseline (config weight) | 0.9661 | 0.3137 | 0.9611 | 0.34 % |
| sqrt weighting | 0.9666 | 0.3194 | 0.9618 | 0.35 % |
| SMOTE | 0.9662 | 0.3071 | 0.9618 | 0.33 % |

Aggregate metrics are strong because Benign dominates; macro-F1 is low because several
minority classes are not separable at the flow level. This is label noise / flow overlap,
not a row-count problem (CVE-2021-25741 has 824 training rows and still reaches recall 0.20).

## Per-class (baseline, temporal test)

| Class | Train rows | Precision | Recall | F1 | Signal |
|---|---|---|---|---|---|
| Benign | ~60k | 0.976 | 0.992 | 0.984 | strong |
| Node-RED Reconnaissance | 2475 | 0.921 | 0.847 | 0.882 | strong |
| CVE-2019-20933 | 193 | 0.591 | 0.542 | 0.565 | usable |
| CVE-2021-43798 | 36 | 0.333 | 0.333 | 0.333 | weak |
| CVE-2021-25741 | 824 | 0.472 | 0.204 | 0.285 | weak |
| CVE-2021-30465 | 131 | 0.556 | 0.152 | 0.238 | weak |
| CVE-2019-5736 | 48 | 0.083 | 0.083 | 0.083 | none |
| Node-RED RCE | 168 | 0.167 | 0.024 | 0.042 | none |
| Node-RED Container Escape | 163 | 0.083 | 0.024 | 0.038 | none |
| CVE-2020-13379 | 56 | 0.000 | 0.000 | 0.000 | none |
| CVE-2022-23648 | 34 | 0.000 | 0.000 | 0.000 | none |

## Reading

- Observable at the flow level: Benign, Reconnaissance (both strong), and partially
  CVE-2019-20933. These carry the macro score.
- Not observable from flow statistics: RCE, Container Escape, CVE-2020-13379,
  CVE-2022-23648, CVE-2019-5736 - their captures are mostly ordinary cluster background,
  so the model cannot tell them from benign or from each other regardless of row count.
- Benign holdout FPR on the dataset's own Grafana capture is 0.34 %. The ~40-100 % false
  positives seen in `reports/simulator_live_validation.md` are on live lab traffic, a
  distribution shift from the dataset - that is what lab-captured training data is for.

## Recommendation

Adopt the `sqrt` variant as the 11-class baseline (best macro-F1, Benign and holdout FPR
unchanged). Keep all 11 labels and document the five unobservable classes honestly rather
than claiming detection. Lab attack-generation (next phase) targets the observable classes
and adds in-distribution benign/recon to fix the live-traffic false positives.
