# Demonstration Guide

How to start, run, demonstrate and stop the **Adaptive Multi-Class Intrusion Detection and Cyber
Deception System for Kubernetes**. Every command is run inside WSL2 Ubuntu, from the project folder.

```bash
cd ~/k8s-adaptive-ids
export KUBECONFIG=$HOME/.kube/config
```

> **Safety.** All "attacks" in this project are harmless and run only inside the lab namespaces:
> * reconnaissance is ordinary HTTP requests to Node-RED;
> * decoy probing is HTTP requests to the decoys;
> * attacks that must never be executed for real (container escapes, runc/containerd CVEs) are shown
>   only as **clearly labelled simulated events**.
>
> Nothing contacts external systems, no exploit code exists in the repository, and production traffic is
> never redirected.

---

## 1. What the system does (in one picture)

```
traffic-benign / recon Job (ids-traffic)
        │  HTTP to Node-RED :1880, Grafana :3000, InfluxDB :8086 (target-apps)
        ▼
   cni0 bridge ──► tcpdump (adaptive 5/10/30 s windows) ──► captures/pcap/*.pcap
        ▼
   CICFlowMeter ──► captures/flows/*.pcap_Flow.csv
        ▼
   ML classifier (ExtraTrees, 11 classes + confidence) ─┐
   Flow-burst detector (many flows, one source → one service) ─┤
        ▼                                                │
   SQLite knowledge base (data/ids.sqlite) ◄─────────────┘
        ▼
   MAPE-K controller (every 5 s): Monitor → Analyze → Plan → Execute → Knowledge
        ▼
   Decoy Deployment + Service in ids-deception  ◄── attacker follows up ──► interactions logged
        ▼
   FastAPI backend (:8000)  ──►  Streamlit SOC dashboard (:8501)
```

| Component | Where | Purpose |
|---|---|---|
| Target apps | namespace `target-apps` | Node-RED, Grafana and InfluxDB: the protected applications |
| Traffic generator | namespace `ids-traffic` | Benign Deployment, plus on-demand recon and decoy-probe Jobs |
| Decoys | namespace `ids-deception` | Fake services created at runtime by the controller |
| Capture service | `src/capture/service.py` | tcpdump on `cni0`, adaptive windows |
| Feature extraction | `src/feature_extraction/cicflowmeter.py` | PCAP → flow CSV (existing CICFlowMeter build) |
| Detection | `src/detection/predictor.py`, `behavior.py` | Per-flow ML classification and flow-burst detection |
| Deception controller | `src/deception/controller.py` | MAPE-K loop, runs inside the backend |
| Backend | `src/backend/app.py` | REST API, Swagger at `/docs` |
| Dashboard | `frontend/app.py` | 7-page SOC dashboard |

---

## 2. Pre-flight checks (run once before presenting)

```bash
kubectl get nodes                                   # node Ready
kubectl -n target-apps get pods                     # nodered, grafana, influxdb Running
kubectl -n ids-traffic get deploy traffic-benign    # benign generator 1/1
kubectl -n ids-deception get deploy,svc             # normally empty (no decoys yet)
ls config/ids-controller.kubeconfig                 # least-privilege identity exists
getcap /usr/bin/tcpdump                             # cap_net_admin,cap_net_raw=eip
```

If something is missing, apply the lab objects once. All of these are idempotent:

```bash
kubectl -n target-apps scale deployment grafana influxdb nodered --replicas=1
kubectl apply -f kubernetes/namespaces/ids-traffic.yaml
kubectl apply -k kubernetes/traffic-generator
kubectl apply -f kubernetes/namespaces/ids-deception.yaml
kubectl apply -k kubernetes/deception
kubectl apply -f kubernetes/rbac/ids-controller.yaml
kubernetes/rbac/create-kubeconfig.sh                # writes config/ids-controller.kubeconfig
```

---

## 3. Starting and stopping the application

| Action | Command |
|---|---|
| Start backend and dashboard | `./start.sh` (or `./start.sh start`) |
| Check status | `./start.sh status` |
| Stop both | `./start.sh stop` |
| Restart (picks up code/config changes) | `./start.sh stop && ./start.sh start` |

The backend and dashboard bind to these addresses:

* Backend API: http://127.0.0.1:8000 (Swagger UI: http://127.0.0.1:8000/docs)
* Dashboard: http://localhost:8501. Open it in the Windows browser; WSL2 forwards localhost.
* Logs: `logs/backend.log`, `logs/frontend.log`, `logs/ids.log`.

The **packet-capture service** is separate, and is started from the dashboard or the API:

| Action | Dashboard | API / CLI |
|---|---|---|
| Start capture | *Live Security Monitoring* → Start monitoring | `curl -X POST localhost:8000/api/capture/start -H 'Content-Type: application/json' -d '{}'`, or `.venv/bin/python -m src.capture.service start` |
| Capture N windows only | window count field | `-d '{"windows": 6}'`, or `... service start --windows 6` |
| Status | *Live Security Monitoring* page | `curl localhost:8000/api/capture/status`, or `... service status` |
| Stop capture | *Live Security Monitoring* → Stop monitoring | `curl -X POST localhost:8000/api/capture/stop`, or `... service stop` |

Automatic deception is **off at start** (`deception.enabled_on_start: false`). Enable it on the
*Adaptive Deception* page, or with `curl -X POST localhost:8000/api/deception/enable`.

### Full shutdown after the demo

```bash
curl -X POST localhost:8000/api/capture/stop        # stop capturing
curl -X POST localhost:8000/api/deception/disable   # no new decoys
kubectl -n ids-deception get deploy,svc             # remove any remaining decoys from the dashboard,
                                                    # or: curl -X DELETE localhost:8000/api/deception/decoys/<name>
./start.sh stop
```

Optional: pause the lab workloads with
`kubectl -n ids-traffic scale deploy traffic-benign --replicas=0` and
`kubectl -n target-apps scale deployment grafana influxdb nodered --replicas=0`.

---

## 4. Option A: automated demonstration (recommended, ~5 minutes)

With the backend running:

```bash
.venv/bin/python scripts/demo_scenario.py
```

The script drives the live cluster through 13 checks and writes **only observed results** to
`reports/deception_test_report.md`. A failed step is reported as failed.

| # | Step | What the audience sees |
|---|---|---|
| 1 | Cluster ready | Node and namespaces |
| 2 | Target apps ready | Node-RED, Grafana and InfluxDB pods |
| 3 | Benign generator running | `traffic-benign` pod |
| 4 | Benign windows captured and classified | PCAP → CSV → detections |
| 5 | No decoy from benign traffic | 0 malicious, 0 decoys |
| 6 | Controlled reconnaissance Job | `recon-job.yaml` runs 300 HTTP requests |
| 7 | Detection | Flow bursts from the recon pod IP |
| 8 | MAPE-K decision | Decision with a human-readable reason |
| 9 | Decoys deployed and healthy | `decoy-http-recon`, `decoy-nodered` (deployment time measured) |
| 10 | Decoy interactions | `decoy-probe-job.yaml`; requests logged and linked to the decision |
| 11 | Records available | Same data through the API and dashboard |
| 12 | Simulated CVE-2019-5736 event | Labelled SIMULATED, never counted as a detection |
| 13 | Cleanup | No managed decoy resources left |

Keep the dashboard open on *Adaptive Deception* while the script runs. Decoys appear, scale and
disappear live.

Performance measurements: `.venv/bin/python scripts/measure_performance.py` (writes
`reports/performance.md`).

---

## 5. Option B: manual, step-by-step demonstration (dashboard-driven)

### Step 1: show normal operation
1. Run `./start.sh` and open http://localhost:8501.
2. On *Kubernetes Status*, show the node, namespaces, target-app pods and the benign generator.
3. On *Live Security Monitoring*, click **Start monitoring**.
4. After 2–3 windows (10 s each), watch the live prediction feed on the same page. Flows are classified **Benign**, and the
   data source is shown as `pcap` (live), not dataset replay.
5. On *Adaptive Deception*, click **Enable**. Point out that no decoy is deployed for benign traffic.

### Step 2: generate an attack (controlled reconnaissance)

```bash
kubectl create -f kubernetes/traffic-generator/recon-job.yaml
kubectl -n ids-traffic get pods -l mode=recon -o wide      # note the recon pod IP = "attacker"
```

The Job requests ~60 common paths (`/admin`, `/.env`, `/flows`, …) on Node-RED: 300 requests at
0.2 s spacing, no exploitation, finishing in about a minute. To vary the scan speed, edit `RECON_REQUESTS`
and `RECON_DELAY` in the Job's `env` before creating it:

| Variant | `RECON_DELAY` | Expected behaviour |
|---|---|---|
| Fast scan | `0.1` | Many flows per window; bursts in every window |
| Default | `0.2` | Bursts in every window (lab: 28–49 flows / 10 s) |
| Slow scan | `1.0` or higher | ≤ ~10 flows / window: **below the burst threshold (15)**. This demonstrates the known limitation for slow scans |

### Step 3: show detection
* On *Live Security Monitoring*, the behavioural alert timeline shows the recon pod IP → Node-RED :1880, with flow
  count and rate.
* On *Attack Classification*, the class, confidence, source/destination, and whether a result came from the
  ML classifier or the behavioural detector.

### Step 4: show the deception response
On *Adaptive Deception*, within one controller cycle (5 s) after the burst is stored:
* a **decision** row with a reason, e.g. a flow burst to :1880 → deploy `http-recon` and `nodered`;
* **active decoys** with profile, replicas, TTL and why they were activated;
* repeated bursts scale `http-recon` up to 3 replicas.

```bash
kubectl -n ids-deception get deploy,svc,pods      # decoys created by the controller
```

### Step 5: the attacker interacts with the decoys

```bash
kubectl create -f kubernetes/traffic-generator/decoy-probe-job.yaml
```

The probe visits `decoy-http-recon` and `decoy-nodered`, as an attacker following up a scan would. On
*Adaptive Deception*, the **Interactions** table fills with source IP, method, path, status and the
linked decision. Each interaction extends the decoy's TTL.

### Step 6: host-level attacks (simulated, never executed)
On *Adaptive Deception* → **Simulated event**, choose e.g. `CVE-2019-5736` and submit. Or use the API:

```bash
curl -X POST localhost:8000/api/deception/test-event -H 'Content-Type: application/json' \
     -d '{"attack_class": "CVE-2019-5736", "confidence": 0.95, "note": "demo"}'
```

The controller deploys the `container-env` decoy. The decision and decoy are marked **SIMULATED**, stored
apart from detections, and excluded from all ML metrics. Explain why: these attacks run inside the
container runtime and cannot be seen in network flows.

### Step 7: model evidence and cleanup
* *Model Performance* shows test metrics, the confusion matrix, per-class results and lab validation.
* Remove decoys with **Remove** on *Adaptive Deception*, or wait for the TTL (600 s) to expire.
* Stop capture, then run `./start.sh stop` (see section 3).

---

## 6. Offline demonstrations (no live traffic needed)

| Demo | How |
|---|---|
| Dataset replay | *Live Security Monitoring* → Historical records and dataset replay, or `curl -X POST localhost:8000/api/detection/run -H 'Content-Type: application/json' -d '{"file": "reconnaissance_20230319T1704.pcap_Flow.csv"}'` (records are tagged `source=dataset`) |
| Classify a CSV from the CLI | `.venv/bin/python -m src.detection.predict_csv <file.csv>` |
| Process a stored PCAP | `curl -X POST localhost:8000/api/capture/process -H 'Content-Type: application/json' -d '{"pcap": "<file>.pcap"}'` |
| Dashboard offline mode | `./start.sh stop`, then start only the dashboard. Pages read SQLite read-only and show an offline banner |
| Test suite | `.venv/bin/python -m pytest -q` |

---

## 7. Useful API calls during the demo

| Purpose | Call |
|---|---|
| Health | `GET /api/health` |
| Overview counters | `GET /api/metrics` |
| Latest detections / alerts | `GET /api/detections/latest`, `GET /api/alerts` |
| Controller state | `GET /api/deception/status` |
| Decisions and their reasons | `GET /api/deception/actions` |
| Decoys / interactions | `GET /api/deception/decoys`, `GET /api/deception/interactions` |
| Manual decoy | `POST /api/deception/decoys` with `{"profile": "grafana"}` |
| Run one MAPE-K cycle now | `POST /api/deception/cycle` |
| Cluster status | `GET /api/kubernetes/status` |
| Model metrics | `GET /api/model/performance` |

The full reference is in `docs/API.md` and http://127.0.0.1:8000/docs.

---

## 8. Talking points: how it works

* **Capture.** One tcpdump process per window on `cni0`, the bridge that carries all pod-to-pod traffic.
  The window is 5 s under heavy traffic (≥ 200 packets/s), 30 s when quiet (≤ 20 packets/s) and 10 s
  otherwise. An exclusive lock prevents overlapping captures.
* **Features.** CICFlowMeter turns each PCAP into bidirectional flows with ~80 statistical features.
  IPs, ports, flow IDs and timestamps are removed before classification to avoid memorisation.
* **Classification.** ExtraTrees, trained on the Kubernetes misuse-detection dataset plus verified lab
  benign traffic, assigns one of 11 classes with a confidence.
* **Behavioural detection.** A source opening ≥ 15 TCP flows to one service within a window, at ≥ 1
  flow/s, is a *flow burst*. In lab measurements, benign sources peak at 7 flows per window and the recon
  pod produces 28–49.
* **MAPE-K controller.**
  * Confidence ≥ 0.9 → act. ≥ 0.6 → act only with repeated detections or a corroborating burst. Benign
    traffic never triggers a decoy.
  * Limits: at most 4 decoys and 3 replicas, TTL 600 s (extended by interactions, capped at 3600 s), and
    deployment cooldowns.
  * Every decision is stored with its reason and evidence.
* **Decoys.** A small static HTTP server serves fake content per profile (Node-RED, Grafana, InfluxDB,
  HTTP recon, Kubernetes inventory, container environment).
  * Hardening: non-root, read-only filesystem, all capabilities dropped, no service-account token, no
    egress at all.
  * Request content is never executed. Every request is logged as one JSON line.
* **Least privilege.** The backend uses the `ids-controller` service account. It can manage
  Deployments/Services only in `ids-deception` and has read-only access elsewhere. There is no
  cluster-admin.

## 9. Honest limitations to state when presenting

* Container escapes and the runc/containerd/kubelet CVEs are **not detectable from network flows**; they
  are shown only as simulated events. Kubernetes audit logging was intentionally left out of scope.
* The fixed burst threshold misses very slow scans (fewer than 15 flows per window).
* Detection is window-based: an alert appears one window (5–30 s) plus under 1 s of processing after the
  traffic.
* The dataset's attack captures are whole-node captures, so most flows labelled as attacks are cluster
  background. See `reports/dataset_quality.md`: only 2,247 of 4,128 "attack" flows carry attack evidence.
* The active model is `v2_et_none` (`reports/model_comparison.md`). It recognises this lab's scanner
  at any rate, but a different scanner only partly; behavioural detection covers the rest
  (`reports/behavioural_detection.md`).
* Attack verdicts on applications without benign training traffic are shown as *Unknown / Requires
  Investigation* and never trigger decoys (`reports/unknown_traffic.md`).
* Learned-threshold behavioural alerts only *show* suspicious behaviour. They trigger a decoy only when
  the ML classifier also flags the same source, because a benign client that speeds up raises them too.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard shows the offline banner | `./start.sh status`. If the backend is stopped, run `./start.sh`, then check `logs/backend.log` |
| Capture start returns 409 | A capture is already running: `curl -X POST localhost:8000/api/capture/stop` |
| Capture fails with permission denied | `getcap /usr/bin/tcpdump` must list `cap_net_raw`. Re-apply with `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump` (needs your sudo) |
| No flows or flow bursts | Check that the benign or recon pods are running and that the capture interface is `cni0` |
| No decoy after recon | Deception must be **enabled**. Check *Adaptive Deception* → decisions for suppress reasons (cooldown, decoy limit) |
| Decoy operations return 503 | Kubernetes unreachable: check `kubectl get nodes` and `config/ids-controller.kubeconfig` |
| Probe Job shows no interactions | The decoys `decoy-http-recon` and `decoy-nodered` must exist before the probe Job is created |

## 11. Where results are written

| File | Contents |
|---|---|
| `reports/deception_test_report.md` | Live demonstration results (13 checks) |
| `reports/performance.md` | Latency, pipeline timings, memory |
| `reports/model_evaluation.md` | Model metrics and lab validation |
| `reports/dataset_quality.md` | Label quality and observability per class |
| `docs/architecture.md` | Architecture, workflow and MAPE-K diagrams |
| `docs/API.md` | API reference |
| `data/ids.sqlite` | Detections, alerts, decisions, decoys, interactions |
