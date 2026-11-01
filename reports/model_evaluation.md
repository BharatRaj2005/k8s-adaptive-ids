# Model Evaluation Report

Generated 2026-11-01 09:33 UTC by `python -m src.detection.report` from `models/*/metrics.json`. All numbers are measured; none are entered by hand.

Active model for detection: **et_dataset_sqrt_lab_v6b** (`config/settings.yaml` → `detection.active_model`).

## Summary

Binary columns treat every non-benign class as "attack". *Holdout FPR* is the share of flows in a whole benign capture, never seen in training, that were classified as an attack.

| Model | Label policy | Split | Classes | Accuracy | Macro P | Macro R | Macro F1 | Weighted F1 | Attack det. rate | Test FPR | Holdout FPR | Single-flow median ms | Batch µs/flow |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| et_dataset_baseline | dataset | temporal | 11 | 0.9661 | 0.3802 | 0.2910 | 0.3137 | 0.9611 | 0.6395 | 0.0078 | 0.0034 | 52.45 | 26.6 |
| et_dataset_smote | dataset | temporal | 11 | 0.9662 | 0.3495 | 0.2926 | 0.3071 | 0.9618 | 0.6589 | 0.0083 | 0.0033 | 49.15 | 36.7 |
| et_dataset_sqrt | dataset | temporal | 11 | 0.9666 | 0.3831 | 0.2942 | 0.3194 | 0.9618 | 0.6512 | 0.0081 | 0.0035 | 48.11 | 24.2 |
| et_dataset_sqrt_lab | dataset | temporal | 11 | 0.9669 | 0.3686 | 0.2854 | 0.3083 | 0.9619 | 0.6483 | 0.0076 | 0.0035 | 37.96 | 25.0 |
| et_dataset_sqrt_lab_recon | dataset | temporal | 11 | 0.9666 | 0.3698 | 0.2907 | 0.3121 | 0.9615 | 0.6473 | 0.0081 | 0.0033 | 42.87 | 27.4 |
| et_dataset_sqrt_lab_v2 | dataset | temporal | 11 | 0.9663 | 0.3830 | 0.2955 | 0.3199 | 0.9613 | 0.6424 | 0.0082 | 0.0035 | 44.01 | 22.4 |
| et_dataset_sqrt_lab_v3 | dataset | temporal | 11 | 0.9667 | 0.3580 | 0.2725 | 0.2985 | 0.9617 | 0.6483 | 0.0079 | 0.0037 | 35.71 | 25.8 |
| et_dataset_sqrt_lab_v4 | dataset | temporal | 11 | 0.9667 | 0.3710 | 0.2834 | 0.3097 | 0.9617 | 0.6492 | 0.0081 | 0.0035 | 37.10 | 32.8 |
| et_dataset_sqrt_lab_v5 | dataset | temporal | 11 | 0.9669 | 0.3674 | 0.2763 | 0.3028 | 0.9619 | 0.6483 | 0.0078 | 0.0035 | 35.22 | 21.9 |
| et_dataset_sqrt_lab_v6 | dataset | temporal | 11 | 0.9666 | 0.3781 | 0.2783 | 0.3071 | 0.9616 | 0.6463 | 0.0081 | 0.0036 | 54.59 | 24.7 |
| et_dataset_sqrt_lab_v6a | dataset | temporal | 11 | 0.9666 | 0.3585 | 0.2721 | 0.2984 | 0.9615 | 0.6444 | 0.0079 | 0.0033 | 52.62 | 29.4 |
| et_dataset_sqrt_lab_v6b (active) | dataset | temporal | 11 | 0.9669 | 0.3750 | 0.2935 | 0.3160 | 0.9619 | 0.6492 | 0.0080 | 0.0033 | 52.07 | 24.6 |
| extratrees_attack_focused | attack_focused | temporal | 3 | 0.9959 | 0.9925 | 0.8023 | 0.8691 | 0.9958 | 0.9047 | 0.0007 | 0.0000 | 26.44 | 17.3 |
| extratrees_attack_focused_lab | attack_focused | temporal | 3 | 0.9962 | 0.9927 | 0.8058 | 0.8711 | 0.9962 | 0.9151 | 0.0007 | 0.0000 | 35.38 | 13.5 |
| extratrees_dataset | dataset | temporal | 11 | 0.9661 | 0.3802 | 0.2910 | 0.3137 | 0.9611 | 0.6395 | 0.0078 | 0.0034 | 37.44 | 24.5 |
| extratrees_dataset_lab | dataset | temporal | 11 | 0.9655 | 0.3347 | 0.2562 | 0.2791 | 0.9602 | 0.6318 | 0.0081 | 0.0033 | 41.54 | 28.8 |
| extratrees_dataset_random | dataset | random | 11 | 0.9693 | 0.4126 | 0.2765 | 0.3082 | 0.9638 | 0.6686 | 0.0057 | 0.0034 | 26.47 | 19.4 |
| lightgbm_attack_focused | attack_focused | temporal | 3 | 0.9983 | 0.9943 | 0.9899 | 0.9921 | 0.9983 | 0.9705 | 0.0006 | 0.0000 | 11.95 | 12.8 |
| lightgbm_attack_focused_lab | attack_focused | temporal | 3 | 0.9976 | 0.9940 | 0.8180 | 0.8781 | 0.9976 | 0.9515 | 0.0006 | 0.0000 | 13.84 | 14.8 |
| lightgbm_dataset | dataset | temporal | 11 | 0.9243 | 0.2834 | 0.3205 | 0.2921 | 0.9394 | 0.7752 | 0.0588 | 0.0231 | 16.52 | 89.4 |
| lightgbm_dataset_lab | dataset | temporal | 11 | 0.9232 | 0.2861 | 0.3283 | 0.2974 | 0.9387 | 0.7791 | 0.0602 | 0.0243 | 16.60 | 81.8 |
| lightgbm_dataset_random | dataset | random | 11 | 0.9410 | 0.2813 | 0.3057 | 0.2870 | 0.9490 | 0.7742 | 0.0398 | 0.0222 | 13.11 | 79.8 |
| lightgbm_dataset_unweighted | dataset | temporal | 11 | 0.9101 | 0.1425 | 0.1365 | 0.1394 | 0.9164 | 0.4545 | 0.0493 | 0.0110 | 15.58 | 52.3 |
| pca_ae_nb_dataset | dataset | temporal | 11 | 0.8728 | 0.0973 | 0.1005 | 0.0968 | 0.8774 | 0.1076 | 0.0710 | 0.0445 | 11.11 | 3.9 |
| v2_et_balanced | evidence | temporal | 5 | 0.9977 | 0.6427 | 0.5969 | 0.5948 | 0.9976 | 0.9794 | 0.0014 | n/a | 45.59 | 30.0 |
| v2_et_none | evidence | temporal | 5 | 0.9982 | 0.7635 | 0.7480 | 0.7290 | 0.9982 | 0.9914 | 0.0013 | n/a | 27.21 | 20.3 |
| v2_et_smote | evidence | temporal | 5 | 0.9969 | 0.7862 | 0.8481 | 0.7729 | 0.9970 | 0.9949 | 0.0028 | n/a | 25.98 | 16.3 |
| v2_et_sqrt | evidence | temporal | 5 | 0.9981 | 0.6440 | 0.5977 | 0.5958 | 0.9980 | 0.9828 | 0.0012 | n/a | 43.81 | 18.7 |
| v2_et_sqrt_selected | evidence | temporal | 5 | 0.9902 | 0.5949 | 0.4500 | 0.5026 | 0.9894 | 0.7427 | 0.0005 | n/a | 42.04 | 24.4 |
| v2_et_sqrt_small | evidence | temporal | 5 | 0.9952 | 0.6291 | 0.5977 | 0.5879 | 0.9952 | 0.9863 | 0.0043 | n/a | 30.20 | 10.9 |
| v2_et_under | evidence | temporal | 5 | 0.9942 | 0.5245 | 0.5479 | 0.5354 | 0.9944 | 0.9949 | 0.0053 | n/a | 28.65 | 21.2 |
| v2_lgbm_balanced | evidence | temporal | 5 | 0.9968 | 0.6962 | 0.6870 | 0.6915 | 0.9967 | 0.9297 | 0.0006 | n/a | 9.12 | 21.5 |
| v2_rf_balanced | evidence | temporal | 5 | 0.9929 | 0.5684 | 0.5483 | 0.5535 | 0.9931 | 0.9914 | 0.0068 | n/a | 23.81 | 9.8 |
| v2_xgb_sqrt | evidence | temporal | 5 | 0.9983 | 0.6963 | 0.6953 | 0.6958 | 0.9981 | 0.9708 | 0.0006 | n/a | 11.58 | 7.0 |

## Per-class results: et_dataset_sqrt_lab_v6b

| Label | Class | Precision | Recall | F1 | Test support |
|---|---|---|---|---|---|
| 0 | Benign | 0.976 | 0.992 | 0.984 | 15118 |
| 1 | CVE-2020-13379 | 0.000 | 0.000 | 0.000 | 14 |
| 2 | Node-RED Reconnaissance | 0.925 | 0.871 | 0.897 | 619 |
| 3 | Node-RED RCE | 0.143 | 0.024 | 0.041 | 42 |
| 4 | Node-RED Container Escape | 0.000 | 0.000 | 0.000 | 41 |
| 5 | CVE-2021-43798 | 0.333 | 0.222 | 0.267 | 9 |
| 6 | CVE-2019-20933 | 0.610 | 0.521 | 0.562 | 48 |
| 7 | CVE-2021-30465 | 0.500 | 0.182 | 0.267 | 33 |
| 8 | CVE-2021-25741 | 0.489 | 0.209 | 0.293 | 206 |
| 9 | CVE-2022-23648 | 0.059 | 0.125 | 0.080 | 8 |
| 10 | CVE-2019-5736 | 0.091 | 0.083 | 0.087 | 12 |

### Confusion matrix (rows = true, columns = predicted)

| true \ pred | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 Benign | 14997 | 11 | 32 | 5 | 8 | 0 | 4 | 6 | 39 | 10 | 6 |
| 1 CVE-2020-13379 | 7 | 0 | 1 | 1 | 0 | 1 | 3 | 0 | 0 | 0 | 1 |
| 2 Node-RED Reconnaissance | 75 | 0 | 539 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 2 |
| 3 Node-RED RCE | 30 | 0 | 2 | 1 | 4 | 0 | 2 | 0 | 2 | 0 | 1 |
| 4 Node-RED Container Escape | 40 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| 5 CVE-2021-43798 | 3 | 0 | 1 | 0 | 0 | 2 | 3 | 0 | 0 | 0 | 0 |
| 6 CVE-2019-20933 | 14 | 1 | 0 | 0 | 0 | 3 | 25 | 0 | 0 | 5 | 0 |
| 7 CVE-2021-30465 | 27 | 0 | 0 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 |
| 8 CVE-2021-25741 | 154 | 0 | 8 | 0 | 0 | 0 | 0 | 0 | 43 | 1 | 0 |
| 9 CVE-2022-23648 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| 10 CVE-2019-5736 | 5 | 1 | 0 | 0 | 1 | 0 | 4 | 0 | 0 | 0 | 1 |

### Unseen benign capture `grafana_20230320T1710`

59 of 17623 flows (0.0033) misclassified as attacks: {'CVE-2021-25741': 30, 'Node-RED Reconnaissance': 12, 'CVE-2021-30465': 4, 'Node-RED RCE': 3, 'CVE-2019-5736': 3, 'CVE-2020-13379': 2, 'CVE-2022-23648': 2, 'CVE-2019-20933': 2, 'Node-RED Container Escape': 1}

### Leakage checks

- Dropped identifier columns: Flow ID, Src IP, Dst IP, Timestamp, Src Port
- Training rows before/after removing duplicate feature vectors: 70100 / 68841
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

From `lab_validation.json` (`python -m src.detection.live_eval --lab-set ...`, generated 2026-11-01T09:32). Ground truth comes from the controlled traffic generator: attacker-pod flows to the attacked port are the attack, its other flows (DNS) are excluded, everything else is benign. *Models with `_lab` in their name were trained with lab sets (listed per model under `lab_train_sets` in `models/registry.json`); report sets that are held out from the active model's training, as a set in a model's training data inflates its score.*

### benign_eval_a (benign): {'benign': 191}

benign generator + cluster background only

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.361 | 0.000 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| v2_et_none | 0.000 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | n/a | n/a | n/a |

### benign_eval_b (benign): {'benign': 1450}

benign generator + cluster background; held out

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.383 | 0.000 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| v2_et_none | 0.001 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | n/a | n/a | n/a |

### fbenign_api_grafana (benign): {'benign': 2433}

fast API ~8/s -> Grafana

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.165 | 0.000 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| v2_et_none | 0.048 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | n/a | n/a | n/a |

### fbenign_burst_nodered (benign): {'benign': 1511}

bursty dashboard refresh -> Node-RED

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.202 | 0.000 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| v2_et_none | 0.111 | 0.013 | n/a | n/a | n/a |
| et_dataset_sqrt_lab | 0.023 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | n/a | n/a | n/a |

### fbenign_poller_nodered (benign): {'benign': 1068}

health/metrics poller -> Node-RED (eval)

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.272 | 0.000 | n/a | n/a | n/a |
| extratrees_dataset_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| v2_et_none | 0.002 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab | 0.000 | 0.000 | n/a | n/a | n/a |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | n/a | n/a | n/a |

### recon_run2 (attack): {'ambiguous': 802, 'benign': 566, 'attack': 202}

recon Job traffic-recon-d8kg6, 200 requests, 0.1 s spacing

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.392 | 0.000 | 0.851 | 0.228 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 0.990 | 0.990 | 0.713 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.970 | 0.970 | 0.688 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 0.970 | 0.970 | 0.708 |

### recon_seq_grafana (attack): {'ambiguous': 795, 'benign': 405, 'attack': 199}

sequential scan -> Grafana (unseen app)

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.328 | 0.000 | 0.955 | 0.000 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 0.819 | 0.819 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 0.879 | 0.879 | 0.377 |

### recon_seq_influx (attack): {'ambiguous': 791, 'benign': 297, 'attack': 198}

sequential scan -> InfluxDB (eval)

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.404 | 0.000 | 0.985 | 0.000 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 0.571 | 0.571 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.030 | 0.000 | 0.000 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 0.949 | 0.949 | 0.783 |

### recon_slow_nodered (attack): {'benign': 1180, 'ambiguous': 196, 'attack': 49}

slow HEAD crawl -> Node-RED

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.342 | 0.000 | 0.959 | 0.000 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 0.980 | 0.980 | 0.184 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 0.898 | 0.898 | 0.673 |

### recon_threaded_nodered (attack): {'ambiguous': 1197, 'benign': 336, 'attack': 300}

unseen scanner (threaded_parallel) -> Node-RED

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.363 | 0.000 | 0.913 | 0.167 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 1.000 | 1.000 | 0.593 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.407 | 0.403 | 0.000 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 0.790 | 0.790 | 0.003 |

### attack_nodered_rce_eval_r1 (attack): {'benign': 818, 'ambiguous': 476, 'attack': 119}

simulated nodered_rce

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.372 | 0.000 | 0.992 | 0.000 | 0.000 |
| extratrees_dataset_lab | 0.001 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 1.000 | 1.000 | 0.992 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 1.000 | 1.000 | 0.975 |

### attack_grafana_traversal_eval_r1 (attack): {'benign': 777, 'ambiguous': 476, 'attack': 119}

simulated grafana_traversal

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.376 | 0.000 | 1.000 | 0.000 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 1.000 | 1.000 | 0.992 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 1.000 | 1.000 | 0.992 |

### attack_influx_authbypass_eval_r1 (attack): {'benign': 871, 'ambiguous': 476, 'attack': 119}

simulated influx_authbypass

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.395 | 0.000 | 0.992 | 0.992 | 0.000 |
| extratrees_dataset_lab | 0.001 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.000 | 0.000 | 0.294 | 0.000 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 1.000 | 1.000 | 0.966 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 1.000 | 0.992 | 0.916 |

### attack_grafana_ssrf_eval (attack): {'ambiguous': 389, 'benign': 188, 'attack': 98}

simulated grafana_ssrf

| Model | Benign FPR | Benign FPR conf≥0.9 | Attack flagged (any class) | Attack correct class | Correct class conf≥0.9 |
|---|---|---|---|---|---|
| extratrees_dataset | 0.399 | 0.000 | 0.990 | 0.122 | 0.000 |
| extratrees_dataset_lab | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_et_none | 0.005 | 0.000 | 1.000 | 0.000 | 0.000 |
| et_dataset_sqrt_lab | 0.000 | 0.000 | 0.827 | 0.000 | 0.000 |
| et_dataset_sqrt_lab_v6b | 0.000 | 0.000 | 1.000 | 1.000 | 0.980 |

## Interpretation

- Classes whose flows are almost entirely background-like cannot be reliably separated from benign traffic by flow features; per-class scores near zero for them are expected, and any non-zero score may come from capture-specific artefacts rather than attack behaviour. These attacks (container escapes, runc/containerd/kubelet CVEs) act on the host or Kubernetes API; network flows alone cannot reliably reveal them. A Kubernetes audit-log monitor would be the appropriate additional input; it was left out of this prototype by decision, and the deception controller for these classes is exercised with clearly labelled simulated events instead.
- The `attack_focused` models remove background-like flows from attack captures and keep only classes with enough remaining samples. Their scores are high but cover fewer classes, and some classes have very small test support; they are not comparable to 11-class results.
- The `random` split is reported only to show how much a random split inflates results compared to the per-capture temporal split.
- `pca_ae_nb` is this project's re-implementation of a PCA + autoencoder + Naive Bayes pipeline. Its results describe this implementation only, not the original paper's results.
- No claim is made that any model here outperforms published results; the evaluation protocols differ.
- On lab traffic, dataset-only models flag ~40 % of benign flows (mostly kubelet probes, which resemble the control-plane flows that carry attack labels in the dataset). Adding only slow lab benign flows (`extratrees_dataset_lab`) removes those false positives but then classifies the controlled recon and attack flows as benign too.
- Lab recon and attack flows become separable per flow once the training data holds both sides of the boundary: recon/attack lab sets *and* benign counterexamples of the same apps at similar rates (fast API clients, bursty refreshes, browsing, pollers). Training on recon alone made the model flag fast benign clients as recon (`reports/mapek_corroboration.md` section 7). Lab attack classes are simulated, marker-only traffic, so lab scores show separability of these shapes, not detection of the real exploits; the dataset-split per-class scores above are not improved by lab data.
