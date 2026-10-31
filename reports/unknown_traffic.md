# Unknown traffic and unseen applications

Generated from `reports/unknown_traffic.json` (`python -m src.detection.loao_eval`, run 2026-10-31T05:52:24Z). Brackets show 95% Wilson intervals.

## Problem

In the model comparison, a model that never saw benign traffic of an application flags most of that application's traffic as an attack. The per-flow classifier only knows the application through its attacks, so any flow to it looks like an attack. Here this is measured per application and three countermeasures are compared.

## Mechanisms (`src/detection/unknown.py`)

A flow is reported as **Unknown / Requires Investigation**, never as an attack, when an enabled check fires:

* `unfamiliar_service`: the classifier says *attack*, but the destination service had fewer than 50 benign training flows (an application-aware baseline). It is built from the training data's benign flows per protocol:port and stored as `service_profile.json` in the model directory.
* `low_confidence`: the winning class probability is below 0.5.
* `out_of_distribution`: the mean distance to the 5 nearest training flows (log-scaled, standardised features) exceeds the 0.999 quantile of that distance on validation flows.

An unknown flow keeps the model's label for reference. It is stored with `status = unknown` and `is_malicious = 0`, so the deception controller never deploys a decoy for it.

## Leave-one-application-out protocol

For each application, all benign flows of its service port are removed from training: dataset captures and lab sets alike. Attack flows stay in training as known attack patterns. Each fold trains the selected recipe (ExtraTrees, no class weighting). The decision threshold and the novelty quantile are calibrated on a validation split of that fold's training pool, which never contains the held-out application. Each fold is scored on:

* **held-out application:** every removed benign flow, plus that application's benign flows in the test split and the lab evaluation sets;
* **known applications:** the remaining benign test and lab flows (the cost of a mechanism);
* **attacks:** the test split's attack flows plus the held-out lab recon run.

Precision counts attack verdicts on all benign flows, held-out and known, as false positives.

## Fold: (none held out)

Decision threshold 0.3, novelty threshold 9.59, 0 benign training flows removed, 14 services with a benign profile. Batch inference including the novelty score: 68 µs/flow.

| Variant | Held-out app: false positive | Held-out app: unknown | Known apps: false positive | Known apps: unknown | Attacks detected | Attacks unknown | Attacks missed | Attacks on held-out app (detected / unknown) | Attack precision |
|---|---|---|---|---|---|---|---|---|---|
| none | – | – | 21/17773 = 0.1% [0.1–0.2] | 0/17773 = 0.0% [0.0–0.0] | 778/785 = 99.1% [98.2–99.6] | 0/785 = 0.0% [0.0–0.5] | 7/785 = 0.9% [0.4–1.8] | – | 0.974 |
| low_confidence | – | – | 12/17773 = 0.1% [0.0–0.1] | 9/17773 = 0.1% [0.0–0.1] | 740/785 = 94.3% [92.4–95.7] | 38/785 = 4.8% [3.5–6.6] | 7/785 = 0.9% [0.4–1.8] | – | 0.984 |
| out_of_distribution | – | – | 21/17773 = 0.1% [0.1–0.2] | 53/17773 = 0.3% [0.2–0.4] | 774/785 = 98.6% [97.5–99.2] | 4/785 = 0.5% [0.2–1.3] | 7/785 = 0.9% [0.4–1.8] | – | 0.974 |
| unfamiliar_service | – | – | 21/17773 = 0.1% [0.1–0.2] | 0/17773 = 0.0% [0.0–0.0] | 778/785 = 99.1% [98.2–99.6] | 0/785 = 0.0% [0.0–0.5] | 7/785 = 0.9% [0.4–1.8] | – | 0.974 |
| all | – | – | 12/17773 = 0.1% [0.0–0.1] | 62/17773 = 0.3% [0.3–0.4] | 739/785 = 94.1% [92.3–95.6] | 39/785 = 5.0% [3.7–6.7] | 7/785 = 0.9% [0.4–1.8] | – | 0.984 |

## Fold: nodered

Decision threshold None, novelty threshold 8.01, 16,614 benign training flows removed, 13 services with a benign profile. Batch inference including the novelty score: 64 µs/flow.

| Variant | Held-out app: false positive | Held-out app: unknown | Known apps: false positive | Known apps: unknown | Attacks detected | Attacks unknown | Attacks missed | Attacks on held-out app (detected / unknown) | Attack precision |
|---|---|---|---|---|---|---|---|---|---|
| none | 19885/20506 = 97.0% [96.7–97.2] | 0/20506 = 0.0% [0.0–0.0] | 2/13881 = 0.0% [0.0–0.1] | 0/13881 = 0.0% [0.0–0.0] | 778/785 = 99.1% [98.2–99.6] | 0/785 = 0.0% [0.0–0.5] | 7/785 = 0.9% [0.4–1.8] | 775 / 0 of 775 | 0.038 |
| low_confidence | 19710/20506 = 96.1% [95.8–96.4] | 306/20506 = 1.5% [1.3–1.7] | 2/13881 = 0.0% [0.0–0.1] | 0/13881 = 0.0% [0.0–0.0] | 778/785 = 99.1% [98.2–99.6] | 2/785 = 0.3% [0.1–0.9] | 5/785 = 0.6% [0.3–1.5] | 775 / 0 of 775 | 0.038 |
| out_of_distribution | 19885/20506 = 97.0% [96.7–97.2] | 0/20506 = 0.0% [0.0–0.0] | 2/13881 = 0.0% [0.0–0.1] | 34/13881 = 0.2% [0.2–0.3] | 777/785 = 99.0% [98.0–99.5] | 4/785 = 0.5% [0.2–1.3] | 4/785 = 0.5% [0.2–1.3] | 775 / 0 of 775 | 0.038 |
| unfamiliar_service | 0/20506 = 0.0% [0.0–0.0] | 19885/20506 = 97.0% [96.7–97.2] | 2/13881 = 0.0% [0.0–0.1] | 0/13881 = 0.0% [0.0–0.0] | 3/785 = 0.4% [0.1–1.1] | 775/785 = 98.7% [97.7–99.3] | 7/785 = 0.9% [0.4–1.8] | 0 / 775 of 775 | 0.600 |
| all | 0/20506 = 0.0% [0.0–0.0] | 20016/20506 = 97.6% [97.4–97.8] | 2/13881 = 0.0% [0.0–0.1] | 34/13881 = 0.2% [0.2–0.3] | 2/785 = 0.3% [0.1–0.9] | 779/785 = 99.2% [98.3–99.6] | 4/785 = 0.5% [0.2–1.3] | 0 / 775 of 775 | 0.500 |

## Fold: grafana

Decision threshold 0.4, novelty threshold 10.11, 15,562 benign training flows removed, 13 services with a benign profile. Batch inference including the novelty score: 68 µs/flow.

| Variant | Held-out app: false positive | Held-out app: unknown | Known apps: false positive | Known apps: unknown | Attacks detected | Attacks unknown | Attacks missed | Attacks on held-out app (detected / unknown) | Attack precision |
|---|---|---|---|---|---|---|---|---|---|
| none | 5297/20316 = 26.1% [25.5–26.7] | 0/20316 = 0.0% [0.0–0.0] | 10/13019 = 0.1% [0.0–0.1] | 0/13019 = 0.0% [0.0–0.0] | 767/785 = 97.7% [96.4–98.5] | 0/785 = 0.0% [0.0–0.5] | 18/785 = 2.3% [1.5–3.6] | – | 0.126 |
| low_confidence | 2831/20316 = 13.9% [13.5–14.4] | 2466/20316 = 12.1% [11.7–12.6] | 10/13019 = 0.1% [0.0–0.1] | 0/13019 = 0.0% [0.0–0.0] | 740/785 = 94.3% [92.4–95.7] | 27/785 = 3.4% [2.4–5.0] | 18/785 = 2.3% [1.5–3.6] | – | 0.207 |
| out_of_distribution | 5297/20316 = 26.1% [25.5–26.7] | 0/20316 = 0.0% [0.0–0.0] | 10/13019 = 0.1% [0.0–0.1] | 22/13019 = 0.2% [0.1–0.3] | 764/785 = 97.3% [95.9–98.2] | 3/785 = 0.4% [0.1–1.1] | 18/785 = 2.3% [1.5–3.6] | – | 0.126 |
| unfamiliar_service | 0/20316 = 0.0% [0.0–0.0] | 5297/20316 = 26.1% [25.5–26.7] | 10/13019 = 0.1% [0.0–0.1] | 0/13019 = 0.0% [0.0–0.0] | 767/785 = 97.7% [96.4–98.5] | 0/785 = 0.0% [0.0–0.5] | 18/785 = 2.3% [1.5–3.6] | – | 0.987 |
| all | 0/20316 = 0.0% [0.0–0.0] | 5297/20316 = 26.1% [25.5–26.7] | 10/13019 = 0.1% [0.0–0.1] | 22/13019 = 0.2% [0.1–0.3] | 740/785 = 94.3% [92.4–95.7] | 27/785 = 3.4% [2.4–5.0] | 18/785 = 2.3% [1.5–3.6] | – | 0.987 |

## Fold: influxdb

Decision threshold 0.3, novelty threshold 8.11, 104 benign training flows removed, 13 services with a benign profile. Batch inference including the novelty score: 128 µs/flow.

| Variant | Held-out app: false positive | Held-out app: unknown | Known apps: false positive | Known apps: unknown | Attacks detected | Attacks unknown | Attacks missed | Attacks on held-out app (detected / unknown) | Attack precision |
|---|---|---|---|---|---|---|---|---|---|
| none | 10/196 = 5.1% [2.8–9.1] | 0/196 = 0.0% [0.0–1.9] | 28/17681 = 0.2% [0.1–0.2] | 0/17681 = 0.0% [0.0–0.0] | 777/785 = 99.0% [98.0–99.5] | 0/785 = 0.0% [0.0–0.5] | 8/785 = 1.0% [0.5–2.0] | 4 / 0 of 4 | 0.953 |
| low_confidence | 0/196 = 0.0% [0.0–1.9] | 10/196 = 5.1% [2.8–9.1] | 11/17681 = 0.1% [0.0–0.1] | 17/17681 = 0.1% [0.1–0.2] | 741/785 = 94.4% [92.6–95.8] | 36/785 = 4.6% [3.3–6.3] | 8/785 = 1.0% [0.5–2.0] | 2 / 2 of 4 | 0.985 |
| out_of_distribution | 10/196 = 5.1% [2.8–9.1] | 0/196 = 0.0% [0.0–1.9] | 28/17681 = 0.2% [0.1–0.2] | 66/17681 = 0.4% [0.3–0.5] | 773/785 = 98.5% [97.3–99.1] | 4/785 = 0.5% [0.2–1.3] | 8/785 = 1.0% [0.5–2.0] | 2 / 2 of 4 | 0.953 |
| unfamiliar_service | 0/196 = 0.0% [0.0–1.9] | 10/196 = 5.1% [2.8–9.1] | 28/17681 = 0.2% [0.1–0.2] | 0/17681 = 0.0% [0.0–0.0] | 773/785 = 98.5% [97.3–99.1] | 4/785 = 0.5% [0.2–1.3] | 8/785 = 1.0% [0.5–2.0] | 0 / 4 of 4 | 0.965 |
| all | 0/196 = 0.0% [0.0–1.9] | 10/196 = 5.1% [2.8–9.1] | 11/17681 = 0.1% [0.0–0.1] | 83/17681 = 0.5% [0.4–0.6] | 738/785 = 94.0% [92.1–95.5] | 39/785 = 5.0% [3.7–6.7] | 8/785 = 1.0% [0.5–2.0] | 0 / 4 of 4 | 0.985 |

## Findings

* Without any check, the held-out application's benign traffic is flagged at a rate that depends on how much its traffic resembles known attacks on the same port. Node-RED is worst because the only known :1880 traffic is reconnaissance.
* `unfamiliar_service` removes these false positives in every fold and leaves known applications unchanged. The fold without a held-out application shows its cost on fully known traffic. The price: attacks against an application without a benign profile are reported as **unknown** instead of as an attack. They are flagged for investigation, not dropped, and the behavioural detector still sees volume-based recon on them.
* `low_confidence` and `out_of_distribution` hardly help. Unfamiliar benign traffic is not *far* from the training data: it resembles known attack traffic on the same port, so the model is confident and the nearest neighbours are close. Both checks also cost unknowns on known traffic and attacks.

## Decision

Active configuration (`config/settings.yaml`, `detection.unknown`): enabled = True, checks ['unfamiliar_service']. The low-confidence and out-of-distribution checks are implemented and evaluated but left off. The active model stays `v2_et_none`; the check only changes how its verdicts are reported.

## Hybrid view

| Situation | Classifier | Behavioural detector | Result |
|---|---|---|---|
| Known application, normal traffic | benign | no alert | **known benign** |
| Known application, known attack pattern | attack (service familiar) | maybe | **known attack**: ML alert and MAPE-K assessment |
| Any application, scan-like volume | any | `flow_burst` / `adaptive_rate` / `slow_scan` | **suspicious behaviour**: behavioural alert and MAPE-K assessment |
| Unfamiliar application or service | attack verdict → unknown | no alert | **requires investigation**: shown, no decoy |

## Limitations

* The service profile is per protocol:port. A new application on a port that is already known inherits that port's profile.
* Only three applications plus infrastructure exist in the data, and the InfluxDB fold has 196 benign flows.
* Attacks against a newly deployed application are not *classified* until benign examples of it are added to training.
