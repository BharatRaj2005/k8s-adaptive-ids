# Dataset quality report

Generated 2026-10-30T19:10:19Z by `python -m src.preprocessing.dataset_report` from `yigitsever/kubernetes-dataset` (64,599 flows, 14 per-capture CSVs, 80 candidate features).

## Why per-flow labels were needed

The published labels are per capture: every flow in an attack capture carries the attack label. Those captures were taken on the whole node, so they also contain DNS, CoreDNS health checks, OVN southbound-database traffic (:6642), API-server traffic (:6443) and MetalLB (:7472) that would exist without any attack. A classifier trained on those labels learns to call ordinary cluster background an attack.

The dataset ships no attack timestamps, attacker addresses or packet captures, only flow CSVs, so per-flow ground truth has to come from evidence inside each capture combined with the scenario definition. The rules are in `config/settings.yaml` → `labeling`, and the code is in `src/preprocessing/labeling.py`:

| Status | Evidence | Rule |
|---|---|---|
| attack | direct | flow to the scenario's **target application** port (Node-RED :1880, Grafana :3000, InfluxDB :8086). A port only counts for a scenario that targets that application. |
| attack | post_compromise | (RCE/escape scenarios only) connection *opened by* the attacked pod, which never opens a connection as a client in any benign capture: the reverse shell to :9001, API-server access, HTTPS downloads |
| background | infrastructure | (protocol:port) signature that recurs in the pure background capture, with neither endpoint involved in the attack |
| background | benign_tuple | the exact client/server/protocol/service tuple occurs in a benign capture, with no attack endpoint involved |
| ambiguous | none | anything else: kept for analysis, **never used for training or as test ground truth** |

Confirmed background flows from attack captures are treated as **benign** (`labeling.background_action`; `exclude` drops them instead).

### Validation of the `direct` rule

The `direct` rule assumes that no benign workload used the applications while attack captures were being recorded. If that held, application ports that the scenario does *not* target should be silent. Flows on each non-targeted application port, per attack capture:

| Capture | Flows on non-targeted application ports |
|---|---|
| attack-pods_20230319T1712 | :3000 = 0, :8086 = 0 |
| cve201920933_20230309T0438 | :1880 = 0, :3000 = 0 |
| cve20195736_20230319T1518 | :1880 = 0, :3000 = 0, :8086 = 0 |
| cve202013379_20230318T2159 | :1880 = 0, :8086 = 0 |
| cve202125741_20230319T1549 | :1880 = 0, :3000 = 0, :8086 = 0 |
| cve202130465_20230319T1601 | :1880 = 0, :3000 = 0, :8086 = 0 |
| cve202143798_20230309T0401 | :1880 = 0, :8086 = 0 |
| cve202223648_20230319T1524 | :1880 = 0, :3000 = 0, :8086 = 0 |
| rce-reverse-shell_20230319T1710 | :3000 = 0, :8086 = 0 |
| reconnaissance_20230319T1704 | :3000 = 0, :8086 = 0 |

Total: **0** flows. Application ports are idle unless attacked, which supports the rule. The benign captures show why a port alone is no evidence: there, every :1880 and :3000 flow comes from the same ingress gateway address as the attacks.

## Captures

| Capture | Label | Flows | Duration (s) | Attack | Background | Ambiguous | Observability |
|---|---|---|---|---|---|---|---|
| attack-pods_20230319T1712 | 4 | 163 | 100.7 | 11 | 152 | 0 | host_runtime |
| background_traffic_20230319T1802 | 0 | 5,297 | 3597.6 | 0 | 0 | 0 | benign |
| cve201920933_20230309T0438 | 6 | 193 | 134.2 | 17 | 176 | 0 | network |
| cve20195736_20230319T1518 | 10 | 48 | 27.2 | 0 | 48 | 0 | host_runtime |
| cve202013379_20230318T2159 | 1 | 56 | 30.2 | 2 | 52 | 2 | network |
| cve202125741_20230319T1549 | 8 | 824 | 554.1 | 0 | 824 | 0 | kubernetes_api |
| cve202130465_20230319T1601 | 7 | 131 | 85.6 | 0 | 131 | 0 | host_runtime |
| cve202143798_20230309T0401 | 5 | 36 | 20.0 | 1 | 35 | 0 | network |
| cve202223648_20230319T1524 | 9 | 34 | 17.7 | 0 | 34 | 0 | host_runtime |
| grafana_20230320T1603 | 0 | 10,956 | 3221.2 | 0 | 0 | 0 | benign |
| grafana_20230320T1710 | 0 | 17,623 | 2477.1 | 0 | 0 | 0 | benign |
| nodered_20230320T1759 | 0 | 26,595 | 4300.6 | 0 | 0 | 0 | benign |
| rce-reverse-shell_20230319T1710 | 3 | 168 | 103.1 | 10 | 158 | 0 | network |
| reconnaissance_20230319T1704 | 2 | 2,475 | 175.9 | 2206 | 269 | 0 | network |

## Label quality per class

Label quality is the fraction of the originally labelled flows that carry attack evidence.

| Class | Original flows | Attack (direct + post-compromise) | Background | Ambiguous | Label quality | Observability | Trained |
|---|---|---|---|---|---|---|---|
| 0 Benign | 60,471 | – | 0 | 0 | 100.0% | benign | yes |
| 1 CVE-2020-13379 | 56 | 2 (2 + 0) | 52 | 2 | 3.6% | network | no |
| 2 Node-RED Reconnaissance | 2,475 | 2206 (2206 + 0) | 269 | 0 | 89.1% | network | yes |
| 3 Node-RED RCE | 168 | 10 (1 + 9) | 158 | 0 | 6.0% | network | yes |
| 4 Node-RED Container Escape | 163 | 11 (3 + 8) | 152 | 0 | 6.7% | host_runtime | yes |
| 5 CVE-2021-43798 | 36 | 1 (1 + 0) | 35 | 0 | 2.8% | network | no |
| 6 CVE-2019-20933 | 193 | 17 (17 + 0) | 176 | 0 | 8.8% | network | yes |
| 7 CVE-2021-30465 | 131 | 0 (0 + 0) | 131 | 0 | 0.0% | host_runtime | no |
| 8 CVE-2021-25741 | 824 | 0 (0 + 0) | 824 | 0 | 0.0% | kubernetes_api | no |
| 9 CVE-2022-23648 | 34 | 0 (0 + 0) | 34 | 0 | 0.0% | host_runtime | no |
| 10 CVE-2019-5736 | 48 | 0 (0 + 0) | 48 | 0 | 0.0% | host_runtime | no |

Across all attack captures, 4,128 flows are labelled as attacks. Of these, **2,247** carry attack evidence, **1,879** are confirmed background and **2** are ambiguous.

A class is trained only when it has at least 10 attack-evidence flows (`labeling.min_class_flows`). Trained attack classes: [2, 3, 4, 6].

### Observability

* **network**: the attack itself sends traffic to the target application, e.g. recon, the InfluxDB auth bypass, the Grafana CVEs and the Node-RED RCE.
* **kubernetes_api**: CVE-2021-25741 is triggered by a pod spec submitted to the API server and takes effect inside the kubelet. Neither step appears on the captured pod network: this capture's API-server flows come from the same infrastructure clients at the same rate as in the benign captures.
* **host_runtime**: CVE-2021-30465, CVE-2022-23648 and CVE-2019-5736 (runc/containerd), and the container escape in `attack-pods`, happen inside the node. These three CVE captures contain **no flow outside cluster background**. The escape capture contains only the Node-RED initial-access chain, which is network-identical to the RCE scenario (class 3).

**The network-flow classifier cannot detect classes 7–10, or the escape step of class 4.** The 11-class mapping is kept for dashboard and API compatibility, but these classes are reported as *not network-observable* rather than given a meaningless F1. Classes 1 and 5 are network-observable, but the dataset holds only 2 and 1 attack flows for them, which is too few to train or evaluate.

### Derived attack intervals

These are the time spans of attack-evidence flows, derived from the flows themselves; the dataset publishes no attack execution times.

| Capture | First | Last | Seconds | Flows |
|---|---|---|---|---|
| attack-pods_20230319T1712 | 2023-03-19 14:12:16.386306 | 2023-03-19 14:13:27.362006 | 71.0 | 11 |
| cve201920933_20230309T0438 | 2023-03-09 01:38:37.412432 | 2023-03-09 01:40:41.143071 | 123.7 | 17 |
| cve202013379_20230318T2159 | 2023-03-18 18:59:39.991179 | 2023-03-18 18:59:41.783662 | 1.8 | 2 |
| cve202143798_20230309T0401 | 2023-03-09 01:01:35.665870 | 2023-03-09 01:01:35.665870 | 0.0 | 1 |
| rce-reverse-shell_20230319T1710 | 2023-03-19 14:10:09.809277 | 2023-03-19 14:11:42.588272 | 92.8 | 10 |
| reconnaissance_20230319T1704 | 2023-03-19 14:04:06.200734 | 2023-03-19 14:07:00.964144 | 174.8 | 2206 |

## Missing and invalid feature values

* Rows with any NaN/inf feature: 26 of 64,599
* NaN by column: {'Flow IAT Mean': 26, 'Flow IAT Std': 26, 'Flow IAT Max': 26, 'Flow IAT Min': 26}
* inf by column: {'Flow Bytes/s': 26, 'Flow Packets/s': 26}
* Negative values by column (CICFlowMeter uses -1 for 'not observed', e.g. initial window bytes): {'Flow IAT Min': 68}
* Constant columns (6): Fwd URG Flags, Bwd URG Flags, URG Flag Count, CWR Flag Count, ECE Flag Count, Subflow Bwd Packets

### Dataset schema vs the local CICFlowMeter build

The dataset has 87 columns and the local build emits 94. Only in the local build: Bwd Act Data Pkts, Bwd Seg Size Min, Bwd TCP Retrans. Count, Fwd TCP Retrans. Count, ICMP Code, ICMP Type, Total Connection Flow Time, Total TCP Retrans. Count. Only in the dataset: Total TCP Flow Time. That column was renamed and redefined (`Total Connection Flow Time`), so it is excluded (`features.exclude_columns`). Columns only in the local build are ignored at inference because the model uses the dataset feature set.

## Duplicates

| | Rows | Duplicate feature vectors | Fraction | Vectors with conflicting labels |
|---|---|---|---|---|
| Original labels | 64,599 | 441 | 0.7% | 51 |
| Evidence labels (trainable flows) | 64,594 | 441 | 0.7% | 0 |

Duplicate fraction per evidence label: 0: 0.7%, 2: 0.0%, 3: 0.0%, 4: 0.0%, 6: 0.0%.

Training removes exact duplicate (features, label) rows *after* the split, within the training part only. Every model records how many test rows have an identical feature vector in training (`leakage_checks` in `metrics.json`).

## Class imbalance

* Original labels: 60,471 benign vs 4,128 attack flows; largest:smallest class = 1779:1.
* Evidence labels: 62,350 benign vs 2,244 attack flows; largest:smallest trained class = 6235:1. Class counts: {0: 62350, 2: 2206, 3: 10, 4: 11, 6: 17}.

The minority classes are tiny: after a 75/25 temporal split, classes 3, 4 and 6 have only a handful of test flows. Their per-class scores carry very wide uncertainty, so `reports/model_comparison.md` gives supports and confidence intervals alongside them.

## Laboratory sets (independent ground truth)

These were recorded on this cluster with the controlled traffic generator. Ground truth comes from the attacker pod address and target port in each manifest. The attacker pod's other flows are ambiguous and excluded; in the recon runs these are its DNS lookups to CoreDNS (UDP 53), several per HTTP request because of the cluster search domains.

| Set | Kind | Windows | Benign | Attack | Ambiguous | Note |
|---|---|---|---|---|---|---|
| benign_eval_a | benign | 3 | 191 | 0 | 0 | benign generator + cluster background only |
| benign_eval_b | benign | 24 | 1450 | 0 | 0 | benign generator + cluster background; held out |
| benign_train | benign | 35 | 2103 | 0 | 0 | benign generator + cluster background; training only |
| recon_run1 | attack | 12 | 703 | 303 | 1208 | recon Job traffic-recon-9lbp6, 300 HTTP requests to Node-RED |
| recon_run2 | attack | 10 | 566 | 202 | 802 | recon Job traffic-recon-d8kg6, 200 requests, 0.1 s spacing |

## Limitations

* The per-flow labels are inferred from evidence, not published ground truth. The rules are conservative: no address or port alone makes a flow an attack, and anything that is neither attack-linked nor confirmed background stays ambiguous.
* `post_compromise` evidence counts every new outbound connection of the attacked pod as attacker activity. That is well supported for the reverse shell (:9001 to a host seen in no benign capture) and for API-server access (the Node-RED pod never calls it in benign data). It is plausible, but unconfirmed, for the HTTPS connections.
* Each attack scenario was executed **once**. No class has independent dataset runs, so dataset-based generalisation to a new execution cannot be measured for any class except via the lab recon runs.
* Background flows confirmed inside attack captures are relabelled as benign. This is correct for infrastructure traffic but means the benign class now includes flows recorded during attacks.
