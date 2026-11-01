# Research summary: Adaptive Multi-Class Intrusion Detection and Cyber Deception for Kubernetes

State of the repository on branch `frontend-monitoring` (commit `38a778a`, 2026-10-31). Every figure below is
copied from a measured artefact in this repository. The source of each figure is named, so it can be traced and
reproduced. No value is estimated or rounded beyond the precision shown in the source.

> **Superseded (2026-11-01):** the active model is now `et_dataset_sqrt_lab_v6b` (11 published-label classes,
> trained with lab recon/benign/attack sets) and decoys require ML corroboration. See
> `reports/mapek_corroboration.md` (sections 7-8) for the current model, policy and validation figures.

| Item | Value |
|---|---|
| Active detection model | `v2_et_none` (ExtraTrees, evidence labels + lab data, tuned attack threshold 0.3) |
| Previous active model (fallback) | `extratrees_dataset_lab` |
| Behavioural detector | fixed flow-burst rule + learned per-service thresholds (`adaptive_rate`, `slow_scan`) |
| Unknown-traffic handling | `unfamiliar_service` check (attack verdict on a service without a benign profile → *Unknown*) |
| Deception | MAPE-K controller, 6 decoy profiles, least-privilege Kubernetes identity |
| Datasets | `yigitsever/kubernetes-dataset` (64,599 flows); 5 lab sets + 3 behaviour sessions; generated dataset `gen-v1` (85,473 captured / 48,414 labelled flows) |
| Test suite | 181 tests passed, 0 failed, 0 skipped (2026-10-31) |

---

## 1. Scope and research questions

The prototype detects attacks against applications on a Kubernetes cluster from network flows, and answers
confirmed attacks with decoy services. It addresses:

1. **Multi-class flow classification** of Kubernetes attack scenarios on CICFlowMeter features.
2. **Label validity**: which classes of a published Kubernetes dataset have network-observable evidence at all.
3. **Generalisation**: to unseen benign applications, unseen scanner implementations and another cluster.
4. **Hybrid detection**: per-flow ML combined with per-source behavioural rules.
5. **Adaptive deception**: a MAPE-K loop that deploys, scales and expires decoys from detection evidence.
6. **Controlled experimentation**: reproducible lab traffic with connection-level ground truth.

## 2. System architecture

```
traffic sources (ids-traffic: benign Deployment, recon/decoy Jobs, Attack Simulator Jobs)
        │ HTTP to Node-RED :1880 · Grafana :3000 · InfluxDB :8086 (target-apps)
        ▼
cni0 bridge ──tcpdump (adaptive 5/10/30 s windows)──► PCAP
        ──CICFlowMeter (GintsEngelen fork)──► flow CSV (94 columns)
        ──preprocessing──► ExtraTrees v2_et_none ──► unknown-traffic check ─┐
        └─────────────► behavioural detector (fixed + learned thresholds) ──┤
                                                                            ▼
                              SQLite knowledge base ◄──► MAPE-K controller ──► decoys (ids-deception)
                                     ▲                                             │ request logs
                                     └───────────── interactions ◄─────────────────┘
                              FastAPI backend (41 operations) ◄── Streamlit dashboard (6 pages)
```

| Component | Implementation | Notes |
|---|---|---|
| Capture | `src/capture/tcpdump.py`, `service.py` | One tcpdump per window on `cni0` (measured as the only interface with all pod traffic and Ethernet framing; `-i any` yields SLL frames that CICFlowMeter misparses). Window: 5 s after ≥ 200 pkt/s, 30 s after ≤ 20 pkt/s, else 10 s. |
| Feature extraction | `src/feature_extraction/cicflowmeter.py` | Existing local CICFlowMeter build; rejects non-Ethernet PCAPs; records `empty`/`failed` conversions. |
| Classifier | `src/detection/predictor.py` | Loads model, preprocessor, feature schema, threshold and service profile from `models/<name>/`. |
| Unknown traffic | `src/detection/unknown.py` | Unknown flows keep the model label, but `is_malicious = 0`; they never trigger decoys. |
| Behavioural detection | `src/detection/behavior.py`, `adaptive_behavior.py` | Per (source, destination service) per window. |
| Deception | `src/deception/controller.py`, `k8s_decoys.py` | MAPE-K loop every 5 s; decoys from a fixed template; static decoy responses only. |
| Knowledge base | `src/utils/db.py` (SQLite) | captures, detections, behaviour alerts, decisions, decoys, interactions, simulated events, simulation runs. |
| Backend / UI | `src/backend/app.py` (FastAPI), `frontend/` (Streamlit) | Dashboard falls back to read-only SQLite when the backend is down. |
| Attack Simulator | `src/simulation/` | Predefined lab traffic Jobs (path enumeration / benign profiles only), run-id tagging, verified cleanup, recovery. |
| Dataset generation | `src/datagen/` | Session capture with connection-level ground truth (Section 4.3). |

### 2.1 MAPE-K deception controller

| Stage | Behaviour |
|---|---|
| Monitor | New malicious detections, behavioural alerts, labelled simulated events, decoy state, decoy request logs. |
| Analyze | Evidence grouped by (source IP, attack class). Confidence ≥ 0.9 → act; ≥ 0.6 → act with ≥ 3 detections in 300 s or a corroborating fixed-rule burst; learned-threshold (medium) alerts act only with an ML detection ≥ 0.6 from the same source; benign/unknown never act. |
| Plan | Attack class (or burst port) → decoy profiles from config, reordered by past engagement; deploy, scale, refresh TTL (duplicate prevention) or suppress (limit, cooldown). |
| Execute | Create / scale / delete Deployments and Services labelled `managed-by=ids-deception-controller` in `ids-deception` only. |
| Knowledge | Every decision with reason and evidence ids; decoy lifecycle; interactions linked to decoy, decision and detection. |

Limits (`config/settings.yaml`): max 4 active decoys, max 3 replicas, TTL 600 s extended per interaction up to
3,600 s, 15 s deployment cooldown, 60 s redeploy cooldown, scale-up at ≥ 20 interactions in 300 s.

| Attack class / evidence | Decoy profile(s) |
|---|---|
| Node-RED Reconnaissance, burst to :1880 | `http-recon` (scaled on repeated evidence), `nodered` |
| Node-RED RCE | `nodered` |
| CVE-2020-13379, CVE-2021-43798, burst to :3000 | `grafana` |
| CVE-2019-20933, burst to :8086 | `influxdb` |
| Container escape, CVE-2021-30465, CVE-2019-5736 | `container-env` |
| CVE-2021-25741 | `k8s-inventory` |
| CVE-2022-23648 | `container-env`, `k8s-inventory` |

### 2.2 Security controls of the lab
* `ids-traffic` egress (NetworkPolicy): only the three application ports, the decoy port and DNS.
* Decoys: ingress only from lab namespaces, no egress, non-root, read-only root FS, all capabilities dropped,
  no service-account token.
* Identities (verified with `kubectl auth can-i`): `ids-controller` manages Deployments/Services only in
  `ids-deception`; `ids-attack-generator` manages Jobs/Pods only in `ids-traffic` and reads pods in `target-apps`.
  Neither can read Secrets, touch `kube-system` or create cluster role bindings.

## 3. Environment and requirements

### 3.1 Hardware and platform (measured)
| Item | Value |
|---|---|
| Host | Ubuntu 26.04.1 LTS on WSL2, 12 CPUs, 7.6 GiB RAM |
| Kubernetes | K3s v1.36.5+k3s1, single node, containerd, flannel (`cni0` bridge) |
| Target applications | `nodered/node-red:latest`, `grafana/grafana:latest`, `influxdb:2.7` (namespace `target-apps`) |
| Traffic generator image | `python:3.13-alpine` |
| CICFlowMeter | GintsEngelen fork, `CICFlowMeterV3-0.0.4-SNAPSHOT.jar`, jnetpcap 1.4.1, OpenJDK 17 |
| Capture | tcpdump with `cap_net_raw,cap_net_admin` (setcap) |
| Python | 3.14.4 (venv) |

### 3.2 Python packages (`requirements.txt`; exact versions from `requirements.lock`)
| Package | Version | Use |
|---|---|---|
| numpy | 2.5.4 | numerics |
| pandas | 3.1.0 | data handling |
| scikit-learn | 1.9.1 | ExtraTrees, Random Forest, preprocessing, metrics |
| lightgbm | 4.7.0 | LightGBM candidates (needs `libgomp.so.1`, vendored) |
| xgboost-cpu | 3.4.1 | XGBoost candidate |
| scipy | 1.18.1 | statistics |
| joblib | 1.6.0 | model persistence |
| pyarrow | 26.0.0 | columnar I/O |
| PyYAML | 6.0.3 | configuration |
| fastapi | 0.162.0 | backend API |
| pydantic | 2.14.2 | request validation |
| uvicorn[standard] | 0.54.0 | ASGI server |
| kubernetes | 37.0.1 | cluster client |
| requests | 2.34.2 | HTTP client |
| psutil | 7.2.2 | resource measurement |
| streamlit | 1.66.1 | dashboard |
| plotly | 7.1.0 | charts |
| pytest | 9.2.0 | tests |
| httpx | 0.28.1 | API tests |

Setup: `./setup.sh` (no root; creates `.venv`, installs requirements, clones the dataset, vendors `libgomp`).

## 4. Datasets

### 4.1 Published dataset: `yigitsever/kubernetes-dataset` (Sever & Dogan, ITU J-FET 2023)

14 per-capture CICFlowMeter CSVs (`benign.csv`/`malicious.csv` are concatenations and are not loaded). 87 columns;
the local CICFlowMeter build emits 94. `Total TCP Flow Time` was redefined in later CICFlowMeter versions and is
excluded. Source: `reports/dataset_quality.md`.

| Label | Scenario | Capture | Published flows | Attack-evidence flows | Label quality | Observability | Trained |
|---|---|---|---|---|---|---|---|
| 0 | Benign | background_traffic, grafana ×2, nodered | 60,471 | – | 100 % | benign | yes |
| 1 | CVE-2020-13379 (Grafana avatar SSRF) | cve202013379 | 56 | 2 | 3.6 % | network | no (too few) |
| 2 | Node-RED Reconnaissance | reconnaissance | 2,475 | 2,206 | 89.1 % | network | yes |
| 3 | Node-RED RCE (reverse shell) | rce-reverse-shell | 168 | 10 | 6.0 % | network | yes |
| 4 | Node-RED Container Escape | attack-pods | 163 | 11 | 6.7 % | host runtime (only the initial-access chain is on the network) | yes |
| 5 | CVE-2021-43798 (Grafana path traversal) | cve202143798 | 36 | 1 | 2.8 % | network | no (too few) |
| 6 | CVE-2019-20933 (InfluxDB auth bypass) | cve201920933 | 193 | 17 | 8.8 % | network | yes |
| 7 | CVE-2021-30465 (runc) | cve202130465 | 131 | 0 | 0.0 % | host runtime | no |
| 8 | CVE-2021-25741 (kubelet subPath) | cve202125741 | 824 | 0 | 0.0 % | Kubernetes API | no |
| 9 | CVE-2022-23648 (containerd) | cve202223648 | 34 | 0 | 0.0 % | host runtime | no |
| 10 | CVE-2019-5736 (runc) | cve20195736 | 48 | 0 | 0.0 % | host runtime | no |

**Key finding (label noise).** The published labels are per capture, and every capture is a whole-node capture. Of
4,128 flows labelled as attacks, 2,247 carry attack evidence, 1,879 are confirmed cluster background (DNS, CoreDNS
health, OVN southbound DB :6642, API server :6443, MetalLB :7472) and 2 are ambiguous. Classes 7–10 contain **no**
flow outside cluster background. These classes are kept in the 11-class mapping for compatibility but reported as
*not network-observable*.

**Evidence labelling** (`src/preprocessing/labeling.py`, rules in `config/settings.yaml` → `labeling`):
* *attack / direct*: a flow to the scenario's target application port; validated by 0 flows on non-targeted
  application ports in every attack capture;
* *attack / post-compromise*: new outbound connections of the attacked pod (RCE / escape scenarios);
* *background*: infrastructure (protocol:port) signatures recurring in the background capture (≥ 20 occurrences),
  or exact benign tuples, with no attack endpoint involved; relabelled benign;
* *ambiguous*: everything else; never used for training or as test ground truth.

After labelling: 62,350 benign vs 2,244 attack flows; trained classes {0, 2, 3, 4, 6}; largest:smallest trained
class 6,235:1. Duplicate feature vectors: 441 (0.7 %), 0 with conflicting evidence labels.

### 4.2 Laboratory sets (this cluster, controlled generator)
Ground truth from attacker pod IP + target port; other attacker-pod flows (DNS) ambiguous and excluded.

| Set | Kind | Windows | Benign | Attack | Ambiguous | Role |
|---|---|---|---|---|---|---|
| benign_train | benign | 35 | 2,103 | 0 | 0 | training |
| benign_eval_a | benign | 3 | 191 | 0 | 0 | evaluation |
| benign_eval_b | benign | 24 | 1,450 | 0 | 0 | evaluation |
| recon_run1 | recon (300 req, 0.2 s spacing) | 12 | 703 | 303 | 1,208 | training |
| recon_run2 | recon (200 req, 0.1 s spacing) | 10 | 566 | 202 | 802 | evaluation |

Behaviour sessions (`data/lab/behavior_sessions/`): session1 (calibration), session2 (recon at 10 / 1 / 0.33 /
0.17 req/s and 4 distributed pods), session3 (benign rate ×3, no attacker), session4 (second scanner on Grafana).

### 4.3 Generated dataset `gen-v1` (`data/generated/`, report `reports/balanced_dataset_analysis.md`)

54 independent capture sessions (one Job and one dedicated `cni0` capture each), 0 failed. Generator v2
(`kubernetes/traffic-generator/datagen_generator.py`) logs every TCP connection with its local port.

* **Benign profiles (6 × 3 tiers):** browse, poller, keepalive_client, burst_refresh, asset_loader, api_consumer, at
  low / normal / high rate; GET/HEAD/conditional GET to valid endpoints of all three apps.
* **Scanners (6 × 3 rates × 2 seeds):** seq_wordlist, shuffled_jitter, keepalive_scanner, threaded_parallel,
  head_crawler, multi_app_sweep; path enumeration only (GET/HEAD/OPTIONS).
* **Ground truth:** a flow gets the session label only if it joins the generator pod IP and a logged local port to a
  targeted application endpoint within the connection lifetime and session window (port reuse resolved by time).
  Generator DNS → ambiguous; boundary-crossing flows → ambiguous; flows not involving the generator → background
  (benign, labelled separately).

| | Flows |
|---|---|
| Captured | 85,473 |
| Valid labelled | 48,414 (Benign 42,805 = 3,896 session + 38,909 background; Reconnaissance 5,609) |
| Ambiguous (excluded) | 37,059 (37,051 generator DNS, 8 port-reuse conflicts) |
| Invalid / exact duplicates | 0 / 0 |
| Logged connections matched to a labelled flow | 9,504 / 9,512 (99.92 %); the 8 unmatched are one session's local-port reuse conflicts (ambiguous) |
| Labelled generator-session flows | 9,505 |

| Split (whole sessions) | Sessions | Benign | Recon |
|---|---|---|---|
| train (natural) | 29 | 23,045 | 2,972 |
| validation (natural) | 8 | 5,641 | 736 |
| test (natural) | 11 | 10,320 | 651 |
| held-out scanner `threaded_parallel` | 6 | 3,759 | 1,250 |
| **balanced training set** | 29 | 1,500 (1,050 session + 450 background) | 1,500 |

Recon flows per scanner: multi_app_sweep 1,350; threaded_parallel 1,250; seq_wordlist 970; shuffled_jitter 970;
head_crawler 859; keepalive_scanner 210. Held-out application for evaluation: InfluxDB (31 sessions touch it).
Only Benign and Reconnaissance were generated: other classes would require exploit traffic (not produced) or are not
network-observable. **No model has been trained on `gen-v1` yet.**

## 5. Preprocessing and features

* Dropped before training (leakage): `Flow ID`, `Src IP`, `Dst IP`, `Timestamp`, `Src Port`; excluded:
  `Total TCP Flow Time`. `Dst Port` and `Protocol` are kept as service indicators.
* Fitted on training data only: ±inf → NaN, median imputation, removal of constant features and of one of each
  pair with |Pearson r| > 0.99, removal of duplicate training rows.
* `v2_et_none`: 80 input features → 58 selected (5 constant, 17 correlated removed).
* Top features by permutation importance (validation, macro-F1 drop): Dst Port 0.1019, Bwd Init Win Bytes 0.0223,
  FIN Flag Count 0.0091, Fwd Packet Length Max 0.0072, Fwd Packet Length Std 0.0064. Reconnaissance differs from
  benign Node-RED traffic mainly in response sizes (Bwd packet lengths); a top-k subset (k = 8) chosen on validation
  lost attack recall on test (74.3 % vs 98.3 %), so all features are kept (`reports/model_comparison.md`).

## 6. Models

### 6.1 Active model `v2_et_none` (`models/v2_et_none/`)
| Parameter | Value |
|---|---|
| Algorithm | ExtraTreesClassifier, 300 trees, min_samples_leaf 1, no class weighting |
| Labels | evidence labels; classes 0, 2, 3, 4, 6 |
| Training data | temporal training part of the dataset (51,554 rows; 51,077 after dedup) + `benign_train` + `recon_run1` |
| Training rows per class | 0: 49,113 · 2: 1,936 · 3: 6 · 4: 9 · 6: 13 |
| Decision rule | malicious if 1 − P(benign) ≥ 0.3; threshold tuned on the latest 20 % of each training capture (highest validation macro F1 with validation benign FPR ≤ 0.5 %) |
| Fit time | 3.1 s |
| Size on disk | 42.2 MB (model + preprocessor) |

### 6.2 Evaluation protocol
* **Split**: temporal; the latest 25 % of every capture is the test set (16,149 flows: 15,566 benign, 573 recon,
  4 RCE, 2 escape, 4 CVE-2019-20933). A per-capture split is impossible because each attack was executed once.
* **Leakage check**: 192 of 16,149 test rows have a feature vector identical to a training row.
* **Benign leave-one-capture-out (LOCO)** and **recon leave-one-run-out (LORO)**, threshold re-tuned in each fold.
* **Independent lab sets** never used for training or tuning.
* **Resources** measured in a fresh process on the same 16k flows.

### 6.3 Results of `v2_et_none` (`models/v2_et_none/metrics.json`, `reports/model_comparison.md`)
| Metric | Value |
|---|---|
| Accuracy | 0.9982 |
| Macro F1 / recall / precision (5 classes) | 0.7290 / 0.7480 / 0.7635 |
| Weighted F1 | 0.9982 |
| Benign false-positive rate (test) | 0.13 % (20 / 15,566) |
| Attack detection rate (any attack class) | 99.14 % (578 / 583) |
| Binary precision | 0.9666 |

| Class | Precision | Recall [95 % Wilson] | F1 | Support |
|---|---|---|---|---|
| Benign | 0.9997 | 0.9987 [0.9980–0.9992] | 0.9992 | 15,566 |
| Node-RED Reconnaissance | 0.9676 | 0.9913 [0.9797–0.9963] | 0.9793 | 573 |
| Node-RED RCE | 0.60 | 0.75 [0.30–0.95] | 0.67 | 4 |
| Node-RED Container Escape | 0.25 | 0.50 [0.09–0.91] | 0.33 | 2 |
| CVE-2019-20933 | 1.00 | 0.50 [0.15–0.85] | 0.67 | 4 |

Confusion matrix (rows true, columns predicted; order Benign, Recon, RCE, Escape, CVE-2019-20933):

| | Benign | Recon | RCE | Escape | CVE-2019-20933 |
|---|---|---|---|---|---|
| Benign | 15,546 | 19 | 0 | 1 | 0 |
| Recon | 5 | 568 | 0 | 0 | 0 |
| RCE | 0 | 0 | 3 | 1 | 0 |
| Escape | 0 | 0 | 1 | 1 | 0 |
| CVE-2019-20933 | 0 | 0 | 1 | 1 | 2 |

Classes 3, 4 and 6 have 2–4 test flows; one flow moves their F1 by 0.2–0.5, and differences between candidates on
these classes are not statistically meaningful. Benign and reconnaissance results rest on thousands of flows.

| Generalisation / lab check | Result |
|---|---|
| Lab benign FPR | `benign_eval_a` 0.0 % (0 / 191), `benign_eval_b` 0.07 % (1 / 1,450); 0 % at confidence ≥ 0.9 |
| Lab recon `recon_run2` (held out) | 99.0 % of 202 attack flows detected and correctly classed; 71.3 % at confidence ≥ 0.9 |
| LOCO benign FPR | background 0.0 %, grafana 1.0 % / 0.1 %, **nodered 74.0 %** (mean 18.8 %) |
| LORO recon recall | `recon_run1` 99.7 %, `recon_run2` 99.0 %, **dataset recon capture 0.0 %** |
| Behaviour session2 flow-level recall (same scanner, other speeds) | 83.3–99.3 % per scenario; benign flows flagged 1 / 5,580 |
| Unseen scanner session4 (Grafana) flow-level recall | 42.1 % (medium rate), 60.0 % (low rate) |

| Resource (fresh process, 16k flows) | Value |
|---|---|
| Model size | 42.2 MB |
| Peak RSS | 367.2 MB |
| Batch inference | 27.25 µs/flow (profile run); 20.3 µs/flow at training time |
| Single-flow latency incl. preprocessing | median 52.67 ms, p95 69.22 ms (profile run); median 27.2 ms, p95 42.2 ms at training time |

### 6.4 Candidate comparison (same protocol; `reports/model_comparison.md`)
| Model | Algorithm / imbalance | Macro F1 | Macro recall | Benign FPR | Attack recall | Lab benign FPR | Lab recon recall | LOCO mean FPR | LORO mean recall | Size MB | Peak RSS MB | Single-flow median ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `extratrees_dataset_lab` (previous active) | ExtraTrees, published labels | 0.399 | 0.480 | 1.59 % | 90.4 % | 0.00 % | 0.0 % | 20.0 % | 0.0 % | 466 | 1,183 | 53.4 |
| `v2_et_balanced` | ExtraTrees, balanced | 0.595 | 0.597 | 0.14 % | 97.9 % | 0.28 % | 99.0 % | 19.1 % | 65.8 % | 53 | 389 | 51.9 |
| `v2_et_sqrt` | ExtraTrees, sqrt weights | 0.596 | 0.598 | 0.12 % | 98.3 % | 0.14 % | 99.0 % | 19.1 % | 66.0 % | 45 | 370 | 53.5 |
| **`v2_et_none` (active)** | ExtraTrees, none | **0.729** | **0.748** | 0.13 % | 99.1 % | 0.07 % | 99.0 % | 18.8 % | 66.2 % | 42 | 367 | 52.7 |
| `v2_et_smote` | ExtraTrees, SMOTE (target 300) | 0.773 | 0.848 | 0.28 % | 99.5 % | 0.28 % | 99.0 % | 18.6 % | 65.8 % | 47 | 375 | 52.7 |
| `v2_et_under` | ExtraTrees, undersampling 10:1 | 0.535 | 0.548 | 0.53 % | 99.5 % | 0.76 % | 99.5 % | 19.5 % | 66.3 % | 34 | 351 | 53.5 |
| `v2_rf_balanced` | Random Forest, balanced subsample | 0.553 | 0.548 | 0.68 % | 99.1 % | 1.72 % | 100.0 % | 8.2 % | 66.4 % | 10 | 307 | 44.2 |
| `v2_lgbm_balanced` | LightGBM, balanced | 0.691 | 0.687 | 0.06 % | 93.0 % | 0.00 % | 98.5 % | 19.1 % | 65.7 % | 6 | 293 | 27.9 |
| `v2_xgb_sqrt` | XGBoost, sqrt weights | 0.696 | 0.695 | 0.06 % | 97.1 % | 0.07 % | 99.0 % | 19.1 % | 65.8 % | 2 | 302 | 31.5 |
| `v2_et_sqrt_selected` | ExtraTrees, top-8 features | 0.503 | 0.450 | 0.05 % | 74.3 % | 0.41 % | 94.1 % | 18.2 % | 61.6 % | 28 | 337 | 52.3 |
| `v2_et_sqrt_small` | ExtraTrees, 100 trees, depth 24 | 0.588 | 0.598 | 0.43 % | 98.6 % | 0.28 % | 99.5 % | 19.0 % | 66.2 % | 12 | 310 | 35.9 |

Selection rationale: `v2_et_none` has the best macro F1 among candidates without oversampling and the lowest lab
benign FPR among ExtraTrees variants. `v2_et_smote` scores higher macro F1, but the gain comes from one or two flows of
classes 3–4 at twice the benign FPR. `v2_xgb_sqrt` is the recommended alternative where memory matters (2 MB).

### 6.5 Earlier model generations (`models/registry.json`; published or attack-focused labels)
Scored on their own label policy, so **not comparable** with Section 6.4.

| Model | Labels | Split | Classes | Accuracy | Macro F1 |
|---|---|---|---|---|---|
| `extratrees_dataset` | published | temporal | 11 | 0.9661 | 0.3137 |
| `extratrees_dataset_lab` | published (+ lab benign) | temporal | 11 | 0.9655 | 0.2791 |
| `extratrees_dataset_random` | published | random | 11 | 0.9693 | 0.3082 |
| `lightgbm_dataset` | published | temporal | 11 | 0.9243 | 0.2921 |
| `lightgbm_dataset_lab` | published (+ lab benign) | temporal | 11 | 0.9232 | 0.2974 |
| `lightgbm_dataset_random` | published | random | 11 | 0.9410 | 0.2870 |
| `lightgbm_dataset_unweighted` | published | temporal | 11 | 0.9101 | 0.1394 |
| `pca_ae_nb_dataset` (base-paper-style reference: PCA + autoencoder + Naive Bayes) | published | temporal | 11 | 0.8728 | 0.0968 |
| `extratrees_attack_focused` | background-like attack flows dropped | temporal | 3 | 0.9959 | 0.8691 |
| `lightgbm_attack_focused` | background-like attack flows dropped | temporal | 3 | 0.9983 | 0.9921 |
| `extratrees_attack_focused_lab` / `lightgbm_attack_focused_lab` | as above + lab benign | temporal | 3 | 0.9962 / 0.9976 | 0.8711 / 0.8781 |

The low macro F1 of the 11-class models reflects the label noise of Section 4.1, not model capacity. The
attack-focused models reach high scores on only 3 classes after removing the noisy flows. No claim is made that any
model outperforms the base paper: the protocols differ.

## 7. Behavioural detection (`reports/behavioural_detection.md`)

Unit: (window, source) pair; 95 % Wilson intervals. Fixed rule: ≥ 15 TCP flows and ≥ 1 flow/s from one source to
one service per window. Adaptive: fixed rule plus learned thresholds `median + 4·max(1.4826·MAD, min_scale)`
(rate, and flows over 120 s).

| Session | Measure | Fixed rule | Adaptive | ML per source | Hybrid | Controller would act |
|---|---|---|---|---|---|---|
| session2 (held-out recon, 5 speeds) | recall | 4.8 % | 51.4 % | 89.5 % | 89.5 % | 93.3 % |
| | FPR (1,276 benign pairs) | 0.0 % | 0.0 % | 0.0 % | 0.0 % | 0.0 % |
| | median delay | 11.7 s | 63.8 s | 3.5 s | 3.5 s | 12.7 s |
| session3 (benign rate ×3, no attacker) | FPR (602 pairs) | 0.0 % | 5.8 % | 0.2 % | 5.8 % | 0.0 % |
| session4 (unseen scanner, Grafana) | recall | 0.0 % | 73.3 % | 76.7 % | 93.3 % | 66.7 % |
| dataset recon (other cluster) | recall | 66.7 % | 94.4 % | – | – | – |
| dataset Node-RED benign behind one gateway IP | FPR (1,400 pairs) | 11.1 % | 19.1 % | – | – | – |

CPU per window (median): fixed 6.7–7.8 ms, adaptive 26.4–31.3 ms; adaptive state 22–72 KiB JSON.

## 8. Unknown traffic and unseen applications (`reports/unknown_traffic.md`)

Leave-one-application-out: all benign flows of one application's port removed from training.

| Held-out app | Held-out benign flagged as attack (no check) | With `unfamiliar_service` (active): attack / unknown | Attacks detected (active) |
|---|---|---|---|
| Node-RED | 97.0 % (19,885 / 20,506) | 0.0 % / 97.0 % | 0.4 % detected, 98.7 % unknown (attacks on the unprofiled app become *unknown*) |
| Grafana | 26.1 % (5,297 / 20,316) | 0.0 % / 26.1 % | 97.7 % |
| InfluxDB | 5.1 % (10 / 196) | 0.0 % / 5.1 % | 98.5 % |
| none held out | – | known-app FPR 0.1 % | 99.1 % |

Unknown verdicts are shown for investigation and never trigger decoys. Inference with the novelty score:
64–128 µs/flow.

## 9. Runtime performance (`reports/performance.md`, 380 classified windows)

| Measure | Median | p95 | Max |
|---|---|---|---|
| Capture window length | 10.1 s | 10.1 s | 10.1 s |
| CICFlowMeter conversion per window | 0.88 s | 1.08 s | 1.54 s |
| Flows per window | 65 | 272 | 525 |
| Prediction per window | 45.8 ms | 81.0 ms | 183.9 ms |
| Window closed → detections stored | 1.05 s | 1.30 s | 2.00 s |
| Decoy deployment (create → ready, n = 5) | 15.3 s | 15.4 s | 15.4 s |
| MAPE-K cycle | 34 ms (last cycle) | | |

RSS: backend 306 MB, capture service 317 MB, dashboard 85 MB. Detection delay ≈ window length (5–30 s) + ≈ 1 s;
processing is window-based, not per packet.

## 10. Live validation (2026-10-31; `reports/simulator_live_validation.md`, `reports/deception_test_report.md`)

| Run (from the dashboard Attack Simulator) | Target | HTTP flows → recon verdicts | Behavioural alerts | Deception |
|---|---|---|---|---|
| Sequential scanner | Node-RED | 282 → 282 (100 %) | 8 fixed-rule | decoys deployed (`http-recon`, `nodered`) |
| Shuffled jitter scanner (3 cancelled runs) | Grafana | 107 → 45, 200 → 86, 100 → 44 (≈ 42–45 %) | 2–6 | refresh / monitor |
| Sequential scanner (backend killed mid-run) | InfluxDB | 155 → 88 (57 %) | 5 high, 1 medium | refresh / monitor |
| **Benign** browsing user (≈ 1.4 req/s) | Node-RED | 79 → **42 false positives (53 %)** | 3 fixed, 2 medium | TTL refreshes of existing decoys |
| **Benign** high-volume API client (8 req/s) | Node-RED | 395 → **395 false positives (100 %)** | 10 fixed | TTL refreshes |
| **Benign** health/metrics poller (1 req/s) | Node-RED | 89 → 3 false positives (3.4 %) | 10 medium | none (await evidence / monitor) |

13-step demonstration: 13 / 13 passed (benign phase 290 flows, 0 malicious, 0 deployments; recon detected by
9 bursts; decoys ready in 15.4–15.5 s; 52 interactions linked to decisions; simulated CVE-2019-5736 event
labelled SIMULATED; full cleanup). Simulator lifecycle (cancel, timeout, backend-interruption recovery, cleanup)
verified; lab objects outside the run unchanged (uid / resourceVersion / restarts).

## 11. Threats to validity and limitations

1. **Single execution per attack scenario** in the published dataset: no independent-run evaluation for classes
   3, 4 and 6; their test supports are 2–4 flows.
2. **Inferred labels**: per-flow labels are evidence-based, not published ground truth. Post-compromise HTTPS
   connections are plausible but unconfirmed attack evidence.
3. **Scanner and application memorisation**: the per-flow model recognises the lab scanner at any rate, but not the
   dataset's scanner (LORO 0 %), and only 42–60 % of other scanners' flows. Reconnaissance training data covers
   Node-RED only.
4. **Benign diversity**: the active model's benign lab data comes from one low-rate generator, so fast or bursty
   legitimate clients are flagged as reconnaissance (Section 10), and the fixed burst rule cannot separate
   high-volume clients or NAT-aggregated users from scanners (Section 7). `gen-v1` was built to address this but has
   not been used for training yet.
5. **Unseen applications**: without benign examples of an application, its traffic looks like an attack (LOCO
   Node-RED 74 %). The `unfamiliar_service` check turns those verdicts into *unknown*, at the cost of also
   turning attacks on that application into *unknown*.
6. **Not network-observable**: host-runtime and kubelet CVEs (classes 7–10) and the escape step of class 4 cannot
   be detected from pod network flows. Kubernetes audit logging was deliberately not used.
7. **Environment**: single-node K3s on WSL2 with flannel; no multi-node or other-CNI evaluation. The dataset was
   recorded on OVN-Kubernetes, which explains part of the cross-cluster gap.
8. **Window-based detection**: 5–30 s windows plus about 1 s of processing; not real-time per packet.
9. **Comparability**: evaluation protocols differ from the base paper. No superiority claim is made.

## 12. Reproducibility

```bash
./setup.sh                                                   # venv, requirements, dataset, libgomp
.venv/bin/python -m src.preprocessing.dataset_report        # reports/dataset_quality.md
.venv/bin/python -m src.detection.experiments                # candidates → reports/model_comparison.json
.venv/bin/python -m src.detection.comparison_report         # reports/model_comparison.md
.venv/bin/python -m src.detection.behavior_eval && .venv/bin/python -m src.detection.behaviour_report
.venv/bin/python -m src.detection.loao_eval                  # reports/unknown_traffic.md
.venv/bin/python -m src.datagen.run && .venv/bin/python -m src.datagen.build   # gen-v1 dataset (cluster needed)
./start.sh && .venv/bin/python scripts/demo_scenario.py      # live 13-step demonstration
.venv/bin/python scripts/measure_performance.py             # reports/performance.md
.venv/bin/python -m pytest -q                                # 181 tests
```

Random state 42 throughout; every model directory stores `training_config.json` (parameters, dataset file hashes,
library versions), `feature_schema.json`, `class_mapping.json`, `decision.json`, `metrics.json` and
`confusion_matrix.csv`.

## 13. Artefact index

| Artefact | Path |
|---|---|
| Configuration | `config/settings.yaml`, `config/datagen.yaml` |
| Models | `models/<name>/`, registry `models/registry.json` |
| Dataset quality | `reports/dataset_quality.md` |
| Model comparison | `reports/model_comparison.md` / `.json` |
| Model evaluation (published-label generation) | `reports/model_evaluation.md` |
| Behavioural detection | `reports/behavioural_detection.md` |
| Unknown traffic | `reports/unknown_traffic.md` |
| Performance | `reports/performance.md` |
| Generated dataset | `data/generated/manifest.json`, `reports/balanced_dataset_analysis.md`, `docs/dataset_generation_plan.md` |
| Live demonstration | `reports/deception_test_report.md`, `reports/simulator_live_validation.md` |
| Architecture / API | `docs/architecture.md`, `docs/API.md` |
| Dataset source | https://github.com/yigitsever/kubernetes-dataset (Sever & Dogan, ITU Journal on Future and Evolving Technologies, 2023) |
