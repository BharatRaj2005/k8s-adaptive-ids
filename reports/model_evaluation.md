# Model Evaluation Report

Generated 2026-10-30 18:29 UTC by `python -m src.detection.report` from `models/*/metrics.json`. All numbers are measured; none are entered by hand.

Active model for detection: **extratrees_dataset_lab** (`config/settings.yaml` → `detection.active_model`).

## Summary

Binary columns treat every non-benign class as "attack". *Holdout FPR* is the share of flows in a whole benign capture, never seen in training, that were classified as an attack.

| Model | Label policy | Split | Classes | Accuracy | Macro P | Macro R | Macro F1 | Weighted F1 | Attack det. rate | Test FPR | Holdout FPR | Single-flow median ms | Batch µs/flow |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| extratrees_attack_focused | attack_focused | temporal | 3 | 0.9959 | 0.9925 | 0.8023 | 0.8691 | 0.9958 | 0.9047 | 0.0007 | 0.0000 | 26.44 | 17.3 |
| extratrees_attack_focused_lab | attack_focused | temporal | 3 | 0.9962 | 0.9927 | 0.8058 | 0.8711 | 0.9962 | 0.9151 | 0.0007 | 0.0000 | 35.38 | 13.5 |
| extratrees_dataset | dataset | temporal | 11 | 0.9661 | 0.3802 | 0.2910 | 0.3137 | 0.9611 | 0.6395 | 0.0078 | 0.0034 | 37.44 | 24.5 |
| extratrees_dataset_lab (active) | dataset | temporal | 11 | 0.9655 | 0.3347 | 0.2562 | 0.2791 | 0.9602 | 0.6318 | 0.0081 | 0.0033 | 41.54 | 28.8 |
| extratrees_dataset_random | dataset | random | 11 | 0.9693 | 0.4126 | 0.2765 | 0.3082 | 0.9638 | 0.6686 | 0.0057 | 0.0034 | 26.47 | 19.4 |
| lightgbm_attack_focused | attack_focused | temporal | 3 | 0.9983 | 0.9943 | 0.9899 | 0.9921 | 0.9983 | 0.9705 | 0.0006 | 0.0000 | 11.95 | 12.8 |
| lightgbm_attack_focused_lab | attack_focused | temporal | 3 | 0.9976 | 0.9940 | 0.8180 | 0.8781 | 0.9976 | 0.9515 | 0.0006 | 0.0000 | 13.84 | 14.8 |
| lightgbm_dataset | dataset | temporal | 11 | 0.9243 | 0.2834 | 0.3205 | 0.2921 | 0.9394 | 0.7752 | 0.0588 | 0.0231 | 16.52 | 89.4 |
| lightgbm_dataset_lab | dataset | temporal | 11 | 0.9232 | 0.2861 | 0.3283 | 0.2974 | 0.9387 | 0.7791 | 0.0602 | 0.0243 | 16.60 | 81.8 |
| lightgbm_dataset_random | dataset | random | 11 | 0.9410 | 0.2813 | 0.3057 | 0.2870 | 0.9490 | 0.7742 | 0.0398 | 0.0222 | 13.11 | 79.8 |
| lightgbm_dataset_unweighted | dataset | temporal | 11 | 0.9101 | 0.1425 | 0.1365 | 0.1394 | 0.9164 | 0.4545 | 0.0493 | 0.0110 | 15.58 | 52.3 |
| pca_ae_nb_dataset | dataset | temporal | 11 | 0.8728 | 0.0973 | 0.1005 | 0.0968 | 0.8774 | 0.1076 | 0.0710 | 0.0445 | 11.11 | 3.9 |

## Per-class results: extratrees_dataset_lab

| Label | Class | Precision | Recall | F1 | Test support |
|---|---|---|---|---|---|
| 0 | Benign | 0.975 | 0.992 | 0.984 | 15118 |
| 1 | CVE-2020-13379 | 0.000 | 0.000 | 0.000 | 14 |
| 2 | Node-RED Reconnaissance | 0.918 | 0.853 | 0.884 | 619 |
| 3 | Node-RED RCE | 0.000 | 0.000 | 0.000 | 42 |
| 4 | Node-RED Container Escape | 0.000 | 0.000 | 0.000 | 41 |
| 5 | CVE-2021-43798 | 0.167 | 0.111 | 0.133 | 9 |
| 6 | CVE-2019-20933 | 0.550 | 0.458 | 0.500 | 48 |
| 7 | CVE-2021-30465 | 0.500 | 0.121 | 0.195 | 33 |
| 8 | CVE-2021-25741 | 0.461 | 0.199 | 0.278 | 206 |
| 9 | CVE-2022-23648 | 0.000 | 0.000 | 0.000 | 8 |
| 10 | CVE-2019-5736 | 0.111 | 0.083 | 0.095 | 12 |

### Confusion matrix (rows = true, columns = predicted)

| true \ pred | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 Benign | 14996 | 11 | 34 | 5 | 8 | 0 | 4 | 4 | 41 | 10 | 5 |
| 1 CVE-2020-13379 | 7 | 0 | 2 | 1 | 0 | 1 | 3 | 0 | 0 | 0 | 0 |
| 2 Node-RED Reconnaissance | 86 | 0 | 528 | 0 | 1 | 0 | 0 | 0 | 3 | 0 | 1 |
| 3 Node-RED RCE | 31 | 0 | 2 | 0 | 4 | 0 | 2 | 0 | 2 | 0 | 1 |
| 4 Node-RED Container Escape | 40 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| 5 CVE-2021-43798 | 4 | 0 | 0 | 0 | 0 | 1 | 4 | 0 | 0 | 0 | 0 |
| 6 CVE-2019-20933 | 17 | 1 | 0 | 0 | 0 | 4 | 22 | 0 | 0 | 4 | 0 |
| 7 CVE-2021-30465 | 27 | 0 | 0 | 0 | 0 | 0 | 1 | 4 | 1 | 0 | 0 |
| 8 CVE-2021-25741 | 155 | 0 | 8 | 0 | 0 | 0 | 0 | 0 | 41 | 1 | 1 |
| 9 CVE-2022-23648 | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 10 CVE-2019-5736 | 5 | 1 | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 1 |

### Unseen benign capture `grafana_20230320T1710`

58 of 17623 flows (0.0033) misclassified as attacks: {'CVE-2021-25741': 32, 'Node-RED Reconnaissance': 10, 'CVE-2021-30465': 4, 'CVE-2019-5736': 3, 'CVE-2020-13379': 2, 'CVE-2022-23648': 2, 'CVE-2019-20933': 2, 'Node-RED RCE': 2, 'Node-RED Container Escape': 1}

### Leakage checks

- Dropped identifier columns: Flow ID, Src IP, Dst IP, Timestamp, Src Port
- Training rows before/after removing duplicate feature vectors: 50552 / 50179
- Test rows whose exact feature vector also occurs in training: 192 of 16150

## Label-noise analysis

Each attack class comes from one whole-node capture in which every flow carries the attack label. Flows matching infrastructure service signatures learned from the training part of the benign background capture (0:0, 17:53, 6:6443, 6:6642, 6:7472, 6:8080, 6:8181; protocol:port) are most likely ordinary cluster traffic recorded during the attack window.

| Label | Class | Flows | Background-like | Fraction | Remaining |
|---|---|---|---|---|---|
| 0 | Benign | 60471 | 19948 | 0.330 | 40523 |
| 1 | CVE-2020-13379 | 56 | 52 | 0.929 | 4 |
| 2 | Node-RED Reconnaissance | 2475 | 269 | 0.109 | 2206 |
| 3 | Node-RED RCE | 168 | 160 | 0.952 | 8 |
| 4 | Node-RED Container Escape | 163 | 157 | 0.963 | 6 |
| 5 | CVE-2021-43798 | 36 | 35 | 0.972 | 1 |
| 6 | CVE-2019-20933 | 193 | 176 | 0.912 | 17 |
| 7 | CVE-2021-30465 | 131 | 129 | 0.985 | 2 |
| 8 | CVE-2021-25741 | 824 | 822 | 0.998 | 2 |
| 9 | CVE-2022-23648 | 34 | 34 | 1.000 | 0 |
| 10 | CVE-2019-5736 | 48 | 48 | 1.000 | 0 |

## Validation on traffic captured in this lab

From `lab_validation.json` (`python -m src.detection.live_eval --lab-set ...`, generated 2026-10-30T17:49). Ground truth comes from the controlled traffic generator: attacker-pod flows to the attacked port are the attack, its other flows (DNS) are excluded, everything else is benign. *Models ending in `_lab` were trained with the `benign_train` set, which does not overlap any set below.*

### benign_eval_a (benign): {'benign': 191}

benign generator + cluster background only

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.361 | 0.000 | n/a | n/a | n/a |
| lightgbm_dataset | 0.377 | 0.277 | n/a | n/a | n/a |
| extratrees_attack_focused | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_attack_focused | 0.079 | 0.058 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| extratrees_attack_focused_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_attack_focused_lab | 0.000 | 0.000 | n/a | n/a | n/a |

### benign_eval_b (benign): {'benign': 1450}

benign generator + cluster background; held out

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.383 | 0.000 | n/a | n/a | n/a |
| lightgbm_dataset | 0.381 | 0.292 | n/a | n/a | n/a |
| extratrees_attack_focused | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_attack_focused | 0.084 | 0.063 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_dataset_lab | 0.001 | 0.000 | n/a | n/a | n/a |
| extratrees_attack_focused_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| lightgbm_attack_focused_lab | 0.000 | 0.000 | n/a | n/a | n/a |

### recon_run1 (attack): {'ambiguous': 1208, 'benign': 703, 'attack': 303}

recon Job traffic-recon-9lbp6, 300 HTTP requests to Node-RED

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.401 | 0.000 | 0.858 | 0.182 | 0.000 |
| lightgbm_dataset | 0.404 | 0.292 | 0.700 | 0.000 | 0.000 |
| extratrees_attack_focused | 0.000 | 0.000 | 0.046 | 0.046 | 0.000 |
| lightgbm_attack_focused | 0.071 | 0.050 | 0.574 | 0.574 | 0.033 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| lightgbm_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| extratrees_attack_focused_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| lightgbm_attack_focused_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

### recon_run2 (attack): {'ambiguous': 802, 'benign': 566, 'attack': 202}

recon Job traffic-recon-d8kg6, 200 requests, 0.1 s spacing

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.392 | 0.000 | 0.851 | 0.228 | 0.000 |
| lightgbm_dataset | 0.412 | 0.297 | 0.752 | 0.000 | 0.000 |
| extratrees_attack_focused | 0.000 | 0.000 | 0.025 | 0.025 | 0.000 |
| lightgbm_attack_focused | 0.085 | 0.064 | 0.644 | 0.644 | 0.059 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| lightgbm_dataset_lab | 0.002 | 0.000 | 0.000 | 0.000 | 0.000 |
| extratrees_attack_focused_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| lightgbm_attack_focused_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

## Interpretation

- Classes whose flows are almost entirely background-like cannot be reliably separated from benign traffic by flow features; per-class scores near zero for them are expected, and any non-zero score may come from capture-specific artefacts rather than attack behaviour. These attacks (container escapes, runc/containerd/kubelet CVEs) act on the host or Kubernetes API; network flows alone cannot reliably reveal them. A Kubernetes audit-log monitor would be the appropriate additional input; it was left out of this prototype by decision, and the deception controller for these classes is exercised with clearly labelled simulated events instead.
- The `attack_focused` models remove background-like flows from attack captures and keep only classes with enough remaining samples. Their scores are high but cover fewer classes, and some classes have very small test support; they are not comparable to 11-class results.
- The `random` split is reported only to show how much a random split inflates results compared to the per-capture temporal split.
- `pca_ae_nb` is this project's re-implementation of a PCA + autoencoder + Naive Bayes pipeline. Its results describe this implementation only, not the original paper's results.
- No claim is made that any model here outperforms published results; the evaluation protocols differ.
- On lab traffic, dataset-only models flag ~40 % of benign flows (mostly kubelet probes, which resemble the control-plane flows that carry attack labels in the dataset). Adding verified lab benign flows removes those false positives but the controlled recon flows are then classified as benign: individual reconnaissance HTTP flows look like benign HTTP flows to the same service. The reconnaissance signal in the lab is per-source volume (tens of flows per window from one pod), which per-flow features cannot express.
