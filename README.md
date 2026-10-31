# Adaptive Multi-Class Intrusion Detection and Cyber Deception System for Kubernetes

A working prototype for a single-node K3s lab that:

1. captures pod traffic on the cluster bridge with tcpdump in adaptive windows,
2. turns each window into CICFlowMeter flow features,
3. classifies every flow into benign or one of ten Kubernetes attack scenarios (multi-class ML),
4. detects per-source flow bursts (reconnaissance behaviour),
5. feeds both evidence streams into a **MAPE-K deception controller** that deploys, scales and expires
   isolated decoy services through a least-privilege Kubernetes identity,
6. logs every decoy interaction, and
7. shows everything on a SOC-style dashboard backed by a FastAPI service.

It also works offline on the published dataset's flow CSVs, and the dashboard keeps showing stored
records when the backend or the cluster is down.

| Document | Content |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Architecture, system workflow and MAPE-K diagrams |
| [docs/API.md](docs/API.md) | API reference (generated from the OpenAPI schema) |
| [reports/model_evaluation.md](reports/model_evaluation.md) | Model evaluation, label-noise analysis, lab validation |
| [reports/deception_test_report.md](reports/deception_test_report.md) | End-to-end demonstration results (live cluster) |
| [reports/performance.md](reports/performance.md) | Measured latencies, deployment times, CPU / memory |

## Status

| Priority | Component | Status |
|---|---|---|
| 1 | Dataset loading + label validation, preprocessing, leakage controls, feature selection | Done, tested |
| 1 | LightGBM, ExtraTrees, PCA + autoencoder + Naive Bayes reference; evaluation + latency | Done, tested |
| 2 | Lab namespaces, traffic generator, capture-interface validation, windowed tcpdump capture | Done, tested |
| 2 | PCAP → CICFlowMeter → CSV → model → SQLite; background capture service; adaptive window | Done, tested |
| 2 | Lab ground-truth sets; validation of all models on lab traffic; flow-burst detector | Done, tested |
| 3 | MAPE-K controller, attack→decoy policy, 6 decoy profiles, RBAC, NetworkPolicies, TTL/cooldown/limits | Done, tested (incl. live cluster) |
| 3 | Decoy interaction logging and knowledge base | Done, tested (incl. live cluster) |
| 3 | Kubernetes audit-log monitor | **Not built** (left out by decision, see below) |
| 4 | FastAPI backend (31 operations), Streamlit dashboard (7 pages, offline fallback) | Done, tested |
| 5 | Repeatable live demonstration (13 checks), diagrams, API docs, reports | Done |

### Improvements (branch `improvements`, 2026-10-31)

| Area | Change | Evidence |
|---|---|---|
| Dataset labels | Evidence-based per-flow labels (attack / background / ambiguous). Host-runtime CVEs (classes 7–10) are documented as not network-observable. | `reports/dataset_quality.md` |
| Classifier | `v2_et_none` (ExtraTrees on evidence labels + lab data, validation-tuned threshold) replaces `extratrees_dataset_lab`, which is kept as a fallback. Ten candidates (ExtraTrees variants, Random Forest, LightGBM, XGBoost; class weights, SMOTE, undersampling, feature subsets) compared under one protocol, including leave-one-capture-out and leave-one-run-out. | `reports/model_comparison.md` |
| Unknown traffic | Attack verdicts on a service without a benign training profile are reported as *Unknown / Requires Investigation* and never trigger decoys. Evaluated leave-one-application-out. | `reports/unknown_traffic.md` |
| Behavioural detection | The fixed flow-burst rule is kept and learned per-service thresholds (`adaptive_rate`, `slow_scan`) are added, never above the fixed level. Evaluated on held-out lab sessions with slow, distributed, changing-benign and unseen-scanner traffic. | `reports/behavioural_detection.md` |
| Deception | Per-source incident correlation (ML, behaviour, earlier interactions); decoy order by attacked service and engagement; interaction profiling (`/api/deception/interaction-summary`). Learned-threshold alerts act only with ML corroboration at ≥ 0.6 confidence. | tests, `reports/deception_test_report.md` |
| Dashboard | The Model Performance page separates the dataset test, model comparison, independent lab results, unseen applications and live counts (known attack / unknown / behavioural). | |

Reproduce: `python -m src.preprocessing.dataset_report`, `python -m src.detection.experiments`,
`python -m src.detection.comparison_report`, `python -m src.detection.behavior_eval` and
`python -m src.detection.behaviour_report`, `python -m src.detection.loao_eval`. The lab sessions are recorded with
`scripts/behaviour_scenarios.py`.

Test suite: `.venv/bin/python -m pytest -q`. Unit tests; real tcpdump and CICFlowMeter runs; API tests;
headless rendering of every dashboard page with and without the backend; and one live-cluster decoy
lifecycle test, which is skipped when the cluster is unreachable.

## Architecture

```
traffic-benign / recon Job (ids-traffic) ──► Node-RED · Grafana · InfluxDB (target-apps)
                    │                                 │
                    └──────────── cni0 bridge ────────┘
                                   │ tcpdump (adaptive 5/10/30 s windows)
                                   ▼
             PCAP ─► CICFlowMeter ─► flow CSV ─► preprocessing ─► ExtraTrees (11 classes)
                                                         └──────► flow-burst detector
                                   ▼
                     SQLite knowledge base ◄──► MAPE-K controller ──► decoys (ids-deception)
                                   ▲                                       │ request logs
                                   └─────────── interactions ◄─────────────┘
                     FastAPI backend ◄── Streamlit dashboard (falls back to SQLite read-only)
```

Mermaid diagrams with details are in [docs/architecture.md](docs/architecture.md).

## Prerequisites

Found on this machine (inspected 2026-10-30) and reused rather than reinstalled:

| Item | Version / state |
|---|---|
| OS | Ubuntu 26.04.1 LTS on WSL2, 12 CPUs, 7.6 GiB RAM |
| Python | 3.14.4 (3.11 not installed; all dependencies have 3.14 wheels) |
| K3s / kubectl | v1.36.5+k3s1, single node, containerd; kubeconfig `~/.kube/config` |
| Target apps | Node-RED, Grafana, InfluxDB in the existing `target-apps` namespace (reused) |
| CICFlowMeter | `~/CICFlowMeter` — GintsEngelen fork built with Maven (the fork used to create the dataset) |
| Java | OpenJDK 17 |
| tcpdump / tshark | installed |

Left untouched: `argocd`, `gitops-demo`, `default/nginx-demo` and all earlier files under `~/k8s-ids`.

**System changes made** (with your approval): `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump`
so capture runs without sudo (undo: `sudo setcap -r /usr/bin/tcpdump`), and scaling the three
`target-apps` Deployments to 1 replica. Nothing else on the system was changed; K3s configuration was
not modified.

## Installation

```bash
cd ~/k8s-adaptive-ids
./setup.sh
```

`setup.sh` needs no root. It creates `.venv` (bootstrapping pip, because the distro Python has no
`ensurepip`), installs `requirements.txt` (exact versions in `requirements.lock`), and clones the dataset.
LightGBM needs `libgomp.so.1`, which is not installed, so the script extracts it from the Ubuntu
`libgomp1` package into `vendor/`; `sudo apt install libgomp1` is the system alternative.

## Dataset preparation

[yigitsever/kubernetes-dataset](https://github.com/yigitsever/kubernetes-dataset) (Sever & Dogan, ITU
J-FET 2023) is cloned to `data/raw/kubernetes-dataset/`. The 14 per-capture CSVs are loaded; `benign.csv`
and `malicious.csv` are exact concatenations of them (verified by a test) and are skipped. The file name →
label mapping is validated on every load:

| Label | Scenario | Capture prefix | Flows |
|---|---|---|---|
| 0 | Benign | background_traffic, grafana ×2, nodered | 60 471 |
| 1 | CVE-2020-13379 | cve202013379 | 56 |
| 2 | Node-RED Reconnaissance | reconnaissance | 2 475 |
| 3 | Node-RED RCE | rce-reverse-shell | 168 |
| 4 | Node-RED Container Escape | attack-pods | 163 |
| 5 | CVE-2021-43798 | cve202143798 | 36 |
| 6 | CVE-2019-20933 | cve201920933 | 193 |
| 7 | CVE-2021-30465 | cve202130465 | 131 |
| 8 | CVE-2021-25741 | cve202125741 | 824 |
| 9 | CVE-2022-23648 | cve202223648 | 34 |
| 10 | CVE-2019-5736 | cve20195736 | 48 |

Findings from inspecting the files (they shaped the design):

* **Label noise.** Every attack class is one whole-node capture in which *every* flow carries the attack
  label, including ordinary control-plane traffic (DNS, OVN DB, CoreDNS health, API server). Using service
  signatures learned only from the benign background capture, 91–100 % of the flows of every attack class
  except Reconnaissance are background-like; CVE-2022-23648 and CVE-2019-5736 have no attack-specific
  flows at all. Per-class results for those classes cannot be expected to be meaningful.
* **Schema versions.** The dataset has 87 columns, the local CICFlowMeter build 94. Every model feature
  exists in both. `Total TCP Flow Time` was renamed and extended to UDP in later CICFlowMeter versions
  (commit 60a7573), so it is excluded rather than aliased.
* **CSV quirk.** The CICFlowMeter fork writes the header row twice; repeated headers are dropped on read.

## Model training

Preprocessing, all fitted on training data only:
* drop `Flow ID`, IPs, `Timestamp` and `Src Port` (leakage);
* map ±inf to NaN (zero-duration flows), then median imputation;
* drop constant features and one of each pair with |r| > 0.99;
* drop duplicate training rows.

**Split.** A per-capture split is impossible because each attack class is a single capture. The
default **temporal** split instead puts the last 25 % of every capture in the test set. Two extra checks:
* a **benign holdout** retrains without a whole benign capture and measures false positives on it;
* a random split is reported for comparison only.

```bash
.venv/bin/python -m src.detection.train --model extratrees --lab-train benign_train \
    --lab-eval benign_eval_a --lab-eval benign_eval_b --lab-eval recon_run1 --lab-eval recon_run2   # active model
.venv/bin/python -m src.detection.train --model lightgbm            # primary candidate
.venv/bin/python -m src.detection.train --model extratrees          # fallback
.venv/bin/python -m src.detection.train --model pca_ae_nb           # base-paper-style reference
.venv/bin/python -m src.detection.train --model lightgbm --label-policy attack_focused
.venv/bin/python -m src.detection.report                            # -> reports/model_evaluation.md
```

Each run saves to `models/<name>/`:
* `model.joblib` and `preprocessor.joblib`
* `class_mapping.json` and `feature_schema.json`
* `metrics.json` (accuracy, macro/weighted P/R/F1, per-class scores, confusion matrix, latency, holdout and lab results, leakage checks)
* `training_config.json` (parameters, dataset file hashes, library versions)
* `confusion_matrix.csv`

Results (temporal split, 16 150 test flows; full tables in `reports/model_evaluation.md`):

| Model | Accuracy | Macro F1 | Weighted F1 | Benign-holdout FPR | Lab benign FPR |
|---|---|---|---|---|---|
| **extratrees_dataset_lab** (active) | 0.966 | 0.279 | 0.960 | 0.33 % | 0.0 % |
| extratrees_dataset | 0.966 | 0.314 | 0.961 | 0.34 % | 36–40 % |
| lightgbm_dataset | 0.924 | 0.292 | 0.939 | 2.3 % | 38–41 % |
| pca_ae_nb_dataset (reference) | 0.873 | 0.097 | 0.877 | 4.5 % | — |

* Macro F1 is low because most attack classes have no learnable attack traffic (label noise above).
  Reconnaissance (F1 ≈ 0.88) and CVE-2019-20933 (≈ 0.5) are the classes with real signal.
* The dataset was recorded on a different cluster (OVN-Kubernetes). On this cluster, dataset-only models
  flag ~40 % of ordinary flows (mainly kubelet probes) as attacks.
* The active model is ExtraTrees trained on the dataset **plus verified benign traffic recorded in this
  lab** (`benign_train`). Its dataset test metrics are essentially unchanged, and false positives on
  held-out lab traffic drop to ~0.
* LightGBM was implemented as the primary candidate. ExtraTrees was chosen because it measured better
  on this data, particularly in false-positive rate.
* No claim is made that any model outperforms the base paper; the evaluation protocols differ.

## Kubernetes deployment

```bash
export KUBECONFIG=$HOME/.kube/config
kubectl -n target-apps scale deployment grafana influxdb nodered --replicas=1     # reuse existing targets
kubectl apply -f kubernetes/namespaces/ids-traffic.yaml
kubectl apply -k kubernetes/traffic-generator          # benign generator + egress NetworkPolicy
kubectl apply -f kubernetes/namespaces/ids-deception.yaml
kubectl apply -k kubernetes/deception                  # decoy server ConfigMap + decoy NetworkPolicy
kubectl apply -f kubernetes/rbac/ids-controller.yaml   # least-privilege identity for the backend
kubernetes/rbac/create-kubeconfig.sh                   # -> config/ids-controller.kubeconfig
```

| Namespace | Contents |
|---|---|
| `target-apps` (existing) | Node-RED, Grafana, InfluxDB — see [kubernetes/targets/README.md](kubernetes/targets/README.md) |
| `ids-traffic` | `traffic-benign` Deployment; on-demand `recon-job.yaml` and `decoy-probe-job.yaml` Jobs |
| `ids-deception` | decoys created at runtime from `kubernetes/deception/decoy-template.yaml`; `ids-controller` ServiceAccount |

* **Traffic generator.**
  * `benign` mode: one request every 1–4 s to the three apps.
  * `recon` mode: a bounded scan of ~60 common paths on Node-RED (300 requests, no exploits).
  * `decoy` mode: visits decoy services, as an attacker following up a scan would.
  * Egress is limited to the three app ports, the decoy port and DNS. A request to an external host
    from inside the pod fails with *Network unreachable*.
* **Controller identity (`ids-controller`).**
  * May create, scale and delete Deployments/Services and read pod logs only in `ids-deception`.
  * May read pods and events in the lab namespaces.
  * Verified with `kubectl auth can-i`: it **cannot** create resources in `target-apps`, read secrets,
    touch `kube-system` or create cluster role bindings.
* **Pod hardening.** All lab pods run as non-root with a read-only root filesystem, all capabilities
  dropped and no service-account token. No `privileged`, `hostNetwork`, `hostPID` or `hostPath`.

## Traffic capture

Interface selection was **measured**: 10-second simultaneous captures while the generator ran.

| Interface | Generator↔target packets | Link type | Verdict |
|---|---|---|---|
| **cni0** | 44 | Ethernet | used: all pod-to-pod traffic, pod IPs after service DNAT |
| pod veth | 44 | Ethernet | one pod only |
| any | 132 (each packet seen 3×) | Linux cooked v2 | duplicates; CICFlowMeter misparses SLL |
| eth0, flannel.1 | 0 | Ethernet | single node: no overlay traffic |

Earlier `-i any` captures in `~/k8s-ids` produced flows with IPs like `122.220.88.8 → 62.22.0.0`; the
converter now rejects non-Ethernet PCAPs with an explanation.

```bash
.venv/bin/python -m src.capture.service start [--windows N] [--no-process]
.venv/bin/python -m src.capture.service status
.venv/bin/python -m src.capture.service stop
```

* **Windowing.** One tcpdump process per window, stopped with SIGINT. Files are written as `.pcap.part`
  and renamed when complete.
* **Adaptive window.** The next window is 5 s after ≥ 200 packets/s, 30 s after ≤ 20 packets/s, and
  10 s otherwise (all in `config/settings.yaml`).
* **Safety.**
  * An exclusive lock prevents overlapping captures.
  * `stop` signals only a PID whose command line is this service.
  * Commands are argument lists, never shell strings.
  * Old processed PCAPs beyond `retain_pcaps` are deleted.

## CICFlowMeter processing

The existing build is wrapped by `src/feature_extraction/cicflowmeter.py`. Its CLI only accepts
directories, so each PCAP is symlinked into its own staging directory. The PCAP's link type is checked
first. Success is reported only once the output CSV exists and parses as a flow file; if CICFlowMeter
writes nothing, the window is recorded as `empty`.

```bash
.venv/bin/python -m src.feature_extraction.cicflowmeter captures/pcap/<file>.pcap   # PCAP -> CSV only
.venv/bin/python -m src.capture.process_pcap captures/pcap/<file>.pcap              # PCAP -> CSV -> detections
.venv/bin/python -m src.capture.process_pcap --pending
.venv/bin/python -m src.detection.predict_csv <csv> --source dataset --save-db      # offline / dataset replay
```

Measured on this machine:
* conversion takes 0.6–0.8 s per 10 s window;
* prediction takes ~40–60 ms per window;
* detections are stored < 1 s after a window closes.

Detection therefore lags traffic by about one window. This is window-based processing, not
packet-by-packet real time (see `reports/performance.md`).

Each prediction record contains:
* flow timestamp, source/destination IP and port, protocol;
* predicted class, confidence and malicious flag;
* capture file, data source (`dataset` / `pcap` / `live`), per-flow processing time, detection time and model.

Fields missing from a CSV stay null.

## Detection of reconnaissance in the lab

Five lab sets were recorded with known ground truth:
* three benign sets;
* two recon runs (300 requests at 0.2 s spacing, and 200 at 0.1 s).

The sets are stored under `data/lab/`, built with `python -m src.preprocessing.lab_data`, and evaluated
with `python -m src.detection.live_eval --lab-set ...`.

* **Per flow, recon is not separable from benign requests.** A single `GET /admin → 404` looks like a
  benign `GET /settings → 200` to the same service. Dataset-only models "detect" recon only because they
  flag ~40 % of all traffic; once lab benign traffic is in training, recon flows are classified benign.
* **Per source and window, recon is unmistakable.**
  * Recon pod: 28–49 TCP flows per 10 s window to Node-RED.
  * Busiest benign TCP source: 7 flows per window (the node polling metrics-server on :10250).
  * The **flow-burst detector** (`src/detection/behavior.py`) alerts at ≥ 15 flows and ≥ 1 flow/s from
    one source to one service.
  * On the recorded lab sets it raised 0 alerts in 62 benign windows and alerted in every window where
    the recon was active.

Both evidence streams feed the MAPE-K controller, and every decision records which stream triggered it.

## Deception mechanism (MAPE-K)

`src/deception/controller.py` runs inside the backend every 5 s. Housekeeping always runs; decisions are
made only while automatic deception is enabled.

| Stage | What it does |
|---|---|
| **Monitor** | Collects new malicious ML detections, flow bursts and simulated test events; decoy status from Kubernetes; decoy interactions from decoy pod logs. |
| **Analyze** | Groups evidence by (source IP, attack class).<br>• confidence ≥ 0.9 → act<br>• ≥ 0.6 → act only with ≥ 3 detections in 300 s or a corroborating flow burst<br>• lower → record and monitor<br>• benign → never deploys |
| **Plan** | Maps the class (or the burst's target port) to decoy profiles from config, preferring profiles that attracted more interactions before. Chooses one of deploy, scale (density), refresh TTL (duplicate prevention), or suppress (decoy limit, cooldown). |
| **Execute** | Creates Deployment + Service from the predefined template, scales replicas, removes expired or manually removed decoys — only resources labelled `managed-by=ids-deception-controller`. |
| **Knowledge** | SQLite: every decision with its reason and evidence IDs; decoy lifecycle and deployment time; interactions linked to the decoy, decision and triggering detection. |

Configurable in `config/settings.yaml`:
* attack→decoy and burst-port→decoy policy;
* confidence thresholds, repeat window and repeat count;
* max 4 active decoys and max 3 replicas;
* TTL of 600 s, extended by each interaction and capped at 3600 s;
* 15 s deployment cooldown and 60 s redeploy cooldown;
* engagement scaling at ≥ 20 interactions in 300 s;
* which detection sources the controller acts on.

| Attack class / evidence | Decoy profile(s) |
|---|---|
| Node-RED Reconnaissance, flow burst to :1880 | `http-recon` (scaled on repeated evidence), `nodered` |
| Node-RED RCE | `nodered` |
| CVE-2020-13379, CVE-2021-43798, burst to :3000 | `grafana` |
| CVE-2019-20933, burst to :8086 | `influxdb` |
| Container escape, CVE-2021-30465, CVE-2019-5736 | `container-env` |
| CVE-2021-25741 | `k8s-inventory` |
| CVE-2022-23648 | `container-env`, `k8s-inventory` |

**Decoys.**
* One stdlib HTTP server (`kubernetes/deception/decoy_server.py`) serves static synthetic documents per
  profile from `profiles.json`.
* Request content is never interpreted or executed. No real data or credentials exist in the container.
* Each request is logged as one JSON line (time, decoy, source IP and port, method, path, status,
  interaction type). The backend collects those lines through the Kubernetes API.
* Decoys have no egress, are reachable only through their own service names from the lab namespaces,
  and **no production traffic is redirected**.

**Simulated events.** The dashboard and `POST /api/deception/test-event` can queue a test event for any
class, for example the runc escape, which must never be executed. Such events:
* are stored in their own table, never among detections;
* are excluded from all ML metrics;
* produce decisions and decoys marked `simulated`, with reasons beginning with `SIMULATED`.

## Frontend

```bash
./start.sh            # backend on 127.0.0.1:8000 (/docs for Swagger), dashboard on http://localhost:8501
./start.sh status
./start.sh stop
```

| Page | Shows |
|---|---|
| Security Overview | Flow counters, active threats, decoys, interactions, model accuracy, cluster status; benign/malicious by source; attack categories; recent detections and decisions |
| Live Traffic Monitoring | Filterable flow table (class, source IP, destination IP, status, data source clearly labelled); flows per minute; flow bursts |
| Attack Classification | Class distribution, mean confidence per class, per-class history heatmap, confidence distribution, detailed records |
| Adaptive Deception | MAPE-K stage, enabled state, active decoys with **why they were activated**, controls (enable/disable, run cycle, manual deploy/remove, labelled simulated event), decision history, interactions, deployment history, policy |
| Traffic Capture | Start/stop capture, process pending, current window, PCAP/CSV names, packets, conversion and classification status, window table, dataset replay |
| Model Performance | Accuracy, macro/weighted metrics, latency, confusion matrix, per-class P/R/F1, all models, lab validation, label-noise analysis |
| Kubernetes Status | Connection, nodes, namespaces, target-app pods, traffic generator, decoy pods and services, recent events |

* **Offline mode.** If the backend is unreachable, pages read stored records directly from SQLite
  (read-only) and show a banner.
* **Colors.** Benign/malicious use status colors with ✓/✕ labels, and series use a palette validated for
  colour-vision deficiency on the dark surface.

## Demonstration

With the backend running:

```bash
.venv/bin/python scripts/demo_scenario.py          # writes reports/deception_test_report.md
.venv/bin/python scripts/measure_performance.py    # writes reports/performance.md
```

The scenario runs the steps from the project brief on the live cluster and records only what it observes:

1. Cluster ready.
2. Target apps ready.
3. Benign generator running.
4. Benign windows captured and classified.
5. No decoy activated by benign traffic.
6. Controlled recon Job.
7. Detection (flow bursts; per-flow ML results reported as measured).
8. Controller decision with reasons.
9. Decoys deployed and healthy (with deployment time).
10. Decoy-probe Job interactions logged and linked to decisions.
11. Records available to the dashboard.
12. Labelled simulated CVE-2019-5736 event handled.
13. Decoys cleaned up, with no managed resources left.

To show it on the dashboard instead, use the Traffic Capture page (start capture), run
`kubectl create -f kubernetes/traffic-generator/recon-job.yaml`, enable deception on the Adaptive
Deception page, then `kubectl create -f kubernetes/traffic-generator/decoy-probe-job.yaml`.

## Design decisions

| Decision | Reason |
|---|---|
| Reuse `target-apps` instead of creating `ids-targets` | The apps already existed with PVCs and NodePorts; duplicates would waste RAM. |
| Python 3.14 instead of 3.11 | Only 3.14 is installed; all dependencies have 3.14 wheels. |
| Capture on `cni0` | Measured: the only interface carrying all pod traffic with Ethernet framing. |
| Temporal split + benign holdout + lab validation | A split by capture is impossible; a random split mixes neighbouring flows. |
| Active model: ExtraTrees + lab benign traffic | Measured lowest false-positive rate on lab traffic, with unchanged dataset metrics. |
| Flow-burst detector alongside the ML model | Lab measurements show recon is only separable per source and window. |
| `frontend/views/` instead of `frontend/pages/` | Any `pages/` directory next to the Streamlit entry point switches Streamlit into legacy multipage mode, which bypasses `app.py` (theme and navigation). |
| `config/` directory added | Thresholds, mappings and paths must be configurable rather than hard-coded. |
| Decoy interactions collected from pod logs | Decoys need no egress at all; the backend pulls logs with the least-privilege identity. |
| Kubernetes audit monitor not built | Left out by your decision. K3s audit logging is also not configured on this host (bare `k3s server`, no `audit-*` flags). Container-escape and runc/containerd/kubelet CVEs therefore have no reliable live signal here; the controller handles them through labelled simulated events. |

## Limitations

* Network flows cannot reveal host-level attacks (container escapes, runtime CVEs); per-class scores for
  those classes are near zero and are reported as such.
* Live attack detection in the lab relies on the flow-burst detector for reconnaissance. A slow scan
  below the threshold (< 15 flows per window) would not be detected.
* Processing is window-based (5–30 s plus < 1 s pipeline time), not real time.
* The lab has one node; nothing was tested on multi-node clusters or other CNIs.
* Memory: the active ExtraTrees model is 445 MB on disk (LightGBM: 15 MB). The capture service measured
  1.1 GB RSS with it loaded, and the backend loads its own copy when it classifies files. On machines
  with little RAM, retrain with fewer or shallower trees (`models.extratrees` in config) or switch
  `detection.active_model` to a LightGBM variant, then re-run the lab validation.
* Lab benign training data covers this lab's background and generator traffic only. New legitimate
  workloads may need new benign recordings (`lab_data snapshot`) and retraining.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `OSError: libgomp.so.1` | `./setup.sh` (vendors it) or `sudo apt install libgomp1` |
| kubectl: permission denied on `/etc/rancher/k3s/k3s.yaml` | `export KUBECONFIG=$HOME/.kube/config` |
| CSV with random IPs and port 0 | PCAP was captured with `-i any`; capture on `cni0` (the converter rejects such files) |
| `tcpdump: ... Operation not permitted` | `getcap /usr/bin/tcpdump` must show `cap_net_admin,cap_net_raw=eip` |
| Capture start returns 409 | A capture is already running: `python -m src.capture.service status` / `stop` |
| Decoy operations return 503 | Cluster unreachable or `config/ids-controller.kubeconfig` missing: run `kubernetes/rbac/create-kubeconfig.sh` |
| Traffic Job cannot reach a decoy | Apply the current `kubernetes/traffic-generator` kustomization (its NetworkPolicy allows the decoy port) |
| Dashboard shows "Backend offline" | `./start.sh status`; logs in `logs/backend.log`; stored records are still shown |
| Sidebar lists raw file names | A `frontend/pages/` directory exists; page modules belong in `frontend/views/` |

## Project layout

```
config/settings.yaml          all tunables          kubernetes/   namespaces, traffic-generator, deception, rbac, targets
src/preprocessing/            dataset, schema, cleaning, splitting, pipeline, lab_data
src/detection/                models, train, evaluate, predictor, predict_csv, behavior, live_eval, report
src/capture/                  tcpdump windows, capture service, process_pcap
src/feature_extraction/       CICFlowMeter wrapper
src/deception/                MAPE-K controller, Kubernetes decoy manager
src/backend/                  FastAPI app, queries, cluster status
src/utils/                    config, logging, SQLite, native-library loader
frontend/                     app.py, views/ (7 pages), components/ (API client with fallback, UI kit)
scripts/                      demo_scenario.py, measure_performance.py, gen_api_docs.py
models/  data/  captures/  reports/  docs/  logs/  tests/
```
