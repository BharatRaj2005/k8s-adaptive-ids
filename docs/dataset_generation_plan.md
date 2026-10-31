# Kubernetes dataset generation and retraining: Phase 1 findings and plan

Branch: `dataset-generation` (from `improvements`, 2026-10-31). Nothing existing is modified or deleted:
`data/raw`, `data/lab`, `models/*`, `reports/*` and `data/ids.sqlite` stay as they are. All new artefacts go
under `data/generated/` and `models/gen_*`.

## 1. What exists (inspected)

| Item | State |
|---|---|
| Published dataset | 64,599 flows, 11 classes. Evidence labels leave 62,350 benign; attack evidence: Recon 2,206, RCE 10, Escape 11, CVE-2019-20933 17, CVE-2020-13379 2, CVE-2021-43798 1, classes 7–10 = 0 (`reports/dataset_quality.md`) |
| Lab sets (`data/lab`) | 3 benign sets (191 / 1,450 / 2,103 flows), 2 recon runs (303 / 202 attack flows), 3 behaviour sessions (JSON ground truth) |
| Active model | `v2_et_none`: ExtraTrees 300 trees, evidence labels + `benign_train` + `recon_run1`, attack threshold 0.3 tuned on validation. Test macro F1 0.729 over 5 classes, benign FPR 0.13 %, lab recon recall 99 %, LORO recall on the dataset recon capture **0 %**, Node-RED LOCO FPR **74 %** |
| Preprocessing | `FlowFeatureCleaner` (inf→NaN, constant + |r|>0.99 drop) + median imputer, fitted on train only; drops Flow ID, IPs, Timestamp, Src Port |
| Generator | `traffic_generator.py` (ConfigMap): `benign` (10 fixed GETs, 1–4 s), `recon` (one sequential 60-path wordlist on Node-RED, or a Grafana variant), `decoy`. Each request is logged as JSON with a timestamp, which gives ground truth |
| Capture | `capture_window()` on `cni0` (Ethernet), `.part` → `.pcap` rename; `convert_pcap()` rejects non-Ethernet, records `empty`/`failed` |
| Ground truth | `lab_data.label_flows`: attacker IP + target port → attack; other attacker-pod flows → ambiguous; everything else → benign. Time window not used |
| Cluster | single node, 12 CPU, 7.6 GiB RAM (≈5 GiB available); Node-RED (latest), Grafana (latest), InfluxDB 2.7 in `target-apps`; egress NetworkPolicy in `ids-traffic` limits generator pods to :1880/:3000/:8086, decoys and DNS |
| Tests | 98 test functions |

## 2. Which classes can get new, real, network-observable samples

| Class | New samples? | Reason |
|---|---|---|
| 0 Benign | **yes** | many profiles, rates, methods, apps, sources |
| 2 Reconnaissance | **yes** | path enumeration is harmless (read-only HTTP requests against lab apps) and can be produced by several independent scanner implementations |
| 3 Node-RED RCE, 4 Escape, 1/5/6 Grafana/InfluxDB CVEs | **no** | producing their traffic means sending exploit or exploit-shaped payloads. This framework does not do that. The classes keep their few dataset evidence flows, and the limit is recorded |
| 7–10 runtime/kubelet CVEs | **no** | not network-observable (host runtime / API server); generating "network evidence" for them would be fabricated |

Consequence: the new *generated* dataset covers 2 classes (Benign, Reconnaissance). The balanced training set
combines it with the dataset's evidence flows for classes 3, 4 and 6 **without duplicating them**. Those classes
stay far below the 1,000-flow target, and the reports say so. No class is invented or oversampled to look balanced.
SMOTE runs only as a separately reported experiment.

## 3. Plan

**Phase 2: generation framework** (`src/datagen/`, config `config/datagen.yaml`)
* Generator v2 (same ConfigMap mechanism, same hardened pod spec, same egress policy). Every request is logged.
  * **Benign profiles**: user browsing of Node-RED editor assets, Grafana UI/health, InfluxDB health/ping, a
    monitoring poller (fixed interval), a keep-alive API client (many requests per TCP connection), a bursty
    "dashboard refresh" client. Rates: low (5–15 s), medium (1–4 s), high (0.1–0.5 s). Methods GET/HEAD and
    `POST` only to the apps' own read endpoints that accept it.
  * **Scanner implementations** (genuinely different code paths, not one script with other parameters):
    1. sequential wordlist, new connection per request (existing behaviour)
    2. shuffled wordlist with random jitter
    3. persistent-connection scanner (`http.client`, keep-alive: many probes in one flow)
    4. threaded parallel scanner (N workers)
    5. HEAD-only slow crawler
    6. multi-application sweep (Grafana/InfluxDB/Node-RED, app-specific wordlists)
  * Rates high / medium / slow; source pods vary because each session is a new Job pod.
* Limits: max requests per session, a minimum delay floor, max session duration (`activeDeadlineSeconds`), and only one
  session at a time (lock). Targets are an allow-list.

**Phase 3: per-session capture pipeline**
* For each session: a session ID and metadata, a dedicated tcpdump on `cni0` → `data/generated/pcaps/<session>.pcap`,
  Job → pod IP + first/last request time from its JSON log, then stop the capture → CICFlowMeter → `flows/` →
  validation. Failures are written to the manifest (`status: failed`, error) and never skipped silently. Cleanup: the Job is deleted after its logs are saved to `raw/`.

**Phase 4: labelling** (`src/datagen/labeling.py`)
* `attack`/`benign_session`: flow between the generator pod IP and the session's target IP:port, starting inside
  [first request − slack, last request + slack].
* `generator_aux`: the generator pod's DNS and other traffic → `Unknown/Ambiguous`, excluded.
* `background`: flows not involving the generator pod → benign background, labelled separately (status column).
* Generator-pod flows outside the time window or to unexpected ports → `Unknown/Ambiguous`.
* Exact duplicates and invalid rows (NaN in all features, negative durations) are removed and counted.

**Phase 5: datasets** (`data/generated/{raw,pcaps,flows,labelled,manifests,reports}`, `manifest.json`)
* Session-grouped split: train / validation / test sessions. Entire scanner implementations and one
  application are held out for the generalisation tests.
* Balanced training set: per-class targets (configurable, default 1,500) are reached by subsampling the majority
  class across sessions. Nothing is duplicated.
* Natural evaluation set: untouched held-out sessions with their real benign/attack ratio.

**Phase 6–7: training and selection**: ET / RF / LightGBM / XGBoost with class weights, threshold tuning on validation
sessions, feature importance, calibration check. Compared against `v2_et_none` on the same held-out sessions.
The model is replaced only if it is better on held-out data. `detection.active_model` changes in config only.

**Phase 8–9**: integration through the existing `FlowPredictor` (same feature schema), the dashboard comparison tab,
new tests, the full suite and the 13-step demo.
