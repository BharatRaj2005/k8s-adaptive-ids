# Behavioural detection: fixed vs adaptive, flow-level ML and hybrid

Generated 2026-10-31T06:14:53 by `python -m src.detection.behavior_eval` and `python -m src.detection.behaviour_report`. Every number comes from recorded capture windows, replayed in time order. Nothing is simulated.

## What is compared

* **Fixed rule** (`src/detection/behavior.py`, unchanged): one source opens ≥ 15 TCP flows to one destination service in a window, at ≥ 1.0 flows/s.
* **Adaptive** (`src/detection/adaptive_behavior.py`): the fixed rule plus two learned thresholds per service (`median + 4·max(1.4826·MAD, min_scale)` of earlier non-alerting values, between a floor and the fixed level):
  * `adaptive_rate`: per-window rate, with at least 5 flows;
  * `slow_scan`: flows over the last 120 s.
  * The fixed rule's thresholds act until a service has 30 values. Alerting values are never learned.
* **ML (per source)**: a source is flagged in a window when the active per-flow model (`v2_et_none`) classifies ≥ 2 of its flows as an attack. This is flow-level ML aggregated per source; the pure flow-level results are in their own table below.
* **Hybrid**: adaptive OR ML, i.e. everything that is shown to the operator. Behavioural and ML alerts stay separate records (`behavior_alerts` vs `detections`), and the controller correlates them per source.
* **Controller would act**: the MAPE-K decision rules replayed on the same evidence. A fixed-rule burst acts. So does ML with one flow at ≥ 0.9 confidence, or 3 flows at ≥ 0.6 within 300 s, or a ≥ 0.6 flow corroborated by a behavioural alert. A learned-threshold alert acts only with a ≥ 0.6 ML flow from the same source within 300 s. This is the deception trigger, which needs a lower false-positive rate than what is merely shown.

**Unit of evaluation:** a (window, source) pair. It is an attack pair when one of the session's attacker pods sent TCP flows in that window, and a benign pair for every other source with TCP flows in the window. The attacker pods are known from the Jobs that ran them. Brackets show 95% Wilson intervals. Delay is the end of the first alerting window minus the first request in the generator's own log.

**Calibration versus evaluation:**
* `session1`, the earlier lab windows, was used while developing the adaptive detector (two bugs were found and fixed on it). Its recon run 1 is also in the ML model's training data. It is calibration only.
* `session2`, `session3` and `session4` were recorded after all parameters were fixed and were never used to change anything. They are the held-out evaluation.
* The dataset replays were never used for development either.

## 1. Held-out lab session: recon at different speeds (session2)

131 windows. The session runs 5 minutes of benign-only traffic, then five recon Jobs one after another, with 1 minute of benign-only traffic between Jobs. The benign generator runs throughout.

| Metric | Fixed rule | Adaptive | ML (per source) | Hybrid (adaptive or ML) | Controller would act |
|---|---|---|---|---|---|
| Detection rate = recall (attack pairs) | 5/105 = 4.8% [2.1–10.7] | 54/105 = 51.4% [42.0–60.8] | 94/105 = 89.5% [82.2–94.0] | 94/105 = 89.5% [82.2–94.0] | 98/105 = 93.3% [86.9–96.7] |
| False-positive rate (benign pairs) | 0/1276 = 0.0% [0.0–0.3] | 0/1276 = 0.0% [0.0–0.3] | 0/1276 = 0.0% [0.0–0.3] | 0/1276 = 0.0% [0.0–0.3] | 0/1276 = 0.0% [0.0–0.3] |
| Precision | 5/5 = 100.0% [56.6–100.0] | 54/54 = 100.0% [93.4–100.0] | 94/94 = 100.0% [96.1–100.0] | 94/94 = 100.0% [96.1–100.0] | 98/98 = 100.0% [96.2–100.0] |
| Detection delay (detected scenarios) | median 11.7 s (n=1) | median 63.8 s (n=7) | median 3.5 s (n=8) | median 3.5 s (n=8) | median 12.7 s (n=8) |
| Alerts per window (mean / max) | 0.04 / 1 | 0.41 / 4 | 0.72 / 4 | 0.72 / 4 | 1.83 / 5 |
| CPU per window (median / p95) | 6.8 / 11.3 ms | 31.3 / 47.1 ms | see note | see note | see note |
| Memory (detector state) | none (stateless) | 72 KiB JSON | see note | see note | see note |

| Scenario | Req/s per pod | Requests | Fixed rule: windows | Adaptive: windows | ML (per source): windows | Hybrid (adaptive or ML): windows | Controller would act: windows | Fixed rule: delay | Adaptive: delay | ML (per source): delay | Hybrid (adaptive or ML): delay | Controller would act: delay |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| high_rate | 10.0 | 300 | 5/7 | 7/7 | 7/7 | 7/7 | 7/7 | 12 s | 2 s | 2 s | 2 s | 2 s |
| medium_rate | 1.0 | 120 | 0/12 | 12/12 | 12/12 | 12/12 | 12/12 | missed | 9 s | 9 s | 9 s | 9 s |
| low_rate | 0.333 | 50 | 0/16 | 7/16 | 15/16 | 15/16 | 15/16 | missed | 93 s | 12 s | 12 s | 12 s |
| very_low_rate | 0.167 | 30 | 0/18 | 0/18 | 8/18 | 8/18 | 15/18 | missed | missed | 18 s | 18 s | 38 s |
| distributed_1 | 0.5 | 60 | 0/13 | 7/13 | 13/13 | 13/13 | 12/13 | missed | 64 s | 3 s | 3 s | 13 s |
| distributed_2 | 0.5 | 60 | 0/13 | 7/13 | 13/13 | 13/13 | 12/13 | missed | 63 s | 3 s | 3 s | 13 s |
| distributed_3 | 0.5 | 60 | 0/13 | 7/13 | 13/13 | 13/13 | 13/13 | missed | 64 s | 4 s | 4 s | 4 s |
| distributed_4 | 0.5 | 60 | 0/13 | 7/13 | 13/13 | 13/13 | 12/13 | missed | 64 s | 3 s | 3 s | 13 s |

Adaptive alert types: {'adaptive_rate': 18, 'flow_burst': 5, 'slow_scan': 31}.

### Flow-level ML on the same windows

Share of each scanner's TCP flows that `v2_et_none` classifies as an attack. Benign flows classified as an attack: 1/5580 = 0.0% [0.0–0.1].

| Scenario | Flows flagged | As Node-RED Reconnaissance | Median confidence |
|---|---|---|---|
| high_rate | 298/300 = 99.3% [97.6–99.8] | 298/300 = 99.3% [97.6–99.8] | 0.94 |
| medium_rate | 119/121 = 98.3% [94.2–99.5] | 119/121 = 98.3% [94.2–99.5] | 0.89 |
| low_rate | 47/49 = 95.9% [86.3–98.9] | 47/49 = 95.9% [86.3–98.9] | 0.66 |
| very_low_rate | 25/30 = 83.3% [66.4–92.7] | 25/30 = 83.3% [66.4–92.7] | 0.72 |
| distributed_1 | 56/60 = 93.3% [84.1–97.4] | 56/60 = 93.3% [84.1–97.4] | 0.63 |
| distributed_2 | 59/61 = 96.7% [88.8–99.1] | 59/61 = 96.7% [88.8–99.1] | 0.63 |
| distributed_3 | 57/59 = 96.6% [88.5–99.1] | 57/59 = 96.6% [88.5–99.1] | 0.63 |
| distributed_4 | 56/60 = 93.3% [84.1–97.4] | 56/60 = 93.3% [84.1–97.4] | 0.63 |

**How far this generalises.** These are new executions, from new pods and at new speeds, of the **same scanner** that produced `recon_run1` in the model's training data: the same path list and the same target. The result shows that the classifier recognises this scanner at any rate. It does **not** show that it recognises other scanners; see section 3.

## 2. Changing benign traffic (session3, no attackers)

The session runs 3 minutes at the normal benign rate, then 6 minutes with the generator's request rate raised about 3× (delay 0.3–1.3 s instead of 1–4 s; the change restarts the pod, which then appears under a new IP), then the normal rate again. Every alert in this session is a false positive.

| Metric | Fixed rule | Adaptive | ML (per source) | Hybrid (adaptive or ML) | Controller would act |
|---|---|---|---|---|---|
| Detection rate = recall (attack pairs) | – | – | – | – | – |
| False-positive rate (benign pairs) | 0/602 = 0.0% [0.0–0.6] | 35/602 = 5.8% [4.2–8.0] | 1/602 = 0.2% [0.0–0.9] | 35/602 = 5.8% [4.2–8.0] | 0/602 = 0.0% [0.0–0.6] |
| Precision | – | 0/35 = 0.0% [0.0–9.9] | 0/1 = 0.0% [0.0–79.3] | 0/35 = 0.0% [0.0–9.9] | – |
| Detection delay (detected scenarios) | – | – | – | – | – |
| Alerts per window (mean / max) | 0.00 / 0 | 1.53 / 3 | 0.02 / 1 | 0.58 / 1 | 0.00 / 0 |
| CPU per window (median / p95) | 6.7 / 9.7 ms | 29.9 / 35.9 ms | see note | see note | see note |
| Memory (detector state) | none (stateless) | 45 KiB JSON | see note | see note | see note |

## 3. Previously unseen scanners

### 3a. Second lab scanner (session4)

A differently built scan that the model never saw: other paths (documented Grafana API and UI endpoints), another target application (Grafana :3000; the model's recon training data is Node-RED only), and its own HEAD/GET mix.

| Metric | Fixed rule | Adaptive | ML (per source) | Hybrid (adaptive or ML) | Controller would act |
|---|---|---|---|---|---|
| Detection rate = recall (attack pairs) | 0/30 = 0.0% [0.0–11.4] | 22/30 = 73.3% [55.6–85.8] | 23/30 = 76.7% [59.1–88.2] | 28/30 = 93.3% [78.7–98.2] | 20/30 = 66.7% [48.8–80.8] |
| False-positive rate (benign pairs) | 0/600 = 0.0% [0.0–0.6] | 0/600 = 0.0% [0.0–0.6] | 0/600 = 0.0% [0.0–0.6] | 0/600 = 0.0% [0.0–0.6] | 0/600 = 0.0% [0.0–0.6] |
| Precision | – | 22/22 = 100.0% [85.1–100.0] | 23/23 = 100.0% [85.7–100.0] | 28/28 = 100.0% [87.9–100.0] | 20/20 = 100.0% [83.9–100.0] |
| Detection delay (detected scenarios) | – | median 43.8 s (n=2) | median 8.4 s (n=2) | median 8.4 s (n=2) | median 53.9 s (n=2) |
| Alerts per window (mean / max) | 0.00 / 0 | 0.37 / 1 | 0.38 / 1 | 0.47 / 1 | 0.90 / 2 |
| CPU per window (median / p95) | 7.8 / 10.2 ms | 30.8 / 41.2 ms | see note | see note | see note |
| Memory (detector state) | none (stateless) | 45 KiB JSON | see note | see note | see note |

| Scenario | Req/s per pod | Requests | Fixed rule: windows | Adaptive: windows | ML (per source): windows | Hybrid (adaptive or ML): windows | Controller would act: windows | Fixed rule: delay | Adaptive: delay | ML (per source): delay | Hybrid (adaptive or ML): delay | Controller would act: delay |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| alt_scanner_medium | 1.0 | 120 | 0/13 | 13/13 | 12/13 | 13/13 | 11/13 | missed | 7 s | 7 s | 7 s | 27 s |
| alt_scanner_low | 0.333 | 50 | 0/17 | 9/17 | 11/17 | 15/17 | 9/17 | missed | 81 s | 10 s | 10 s | 81 s |

| Scenario | Flows flagged by ML | As Node-RED Reconnaissance | Median confidence |
|---|---|---|---|
| alt_scanner_medium | 61/145 = 42.1% [34.3–50.2] | 61/145 = 42.1% [34.3–50.2] | 0.75 |
| alt_scanner_low | 36/60 = 60.0% [47.4–71.4] | 36/60 = 60.0% [47.4–71.4] | 0.51 |

### 3b. The dataset's own recon tool (other scanner, other cluster)

The dataset's reconnaissance capture, cut into 10 s windows by flow start time (18 windows). It is preceded by 180 windows of the dataset's benign Node-RED capture, which only warm up the adaptive state and are not scored. ML is not scored here because the model was trained on part of this capture. The model-comparison leave-one-run-out result is the ML evidence: a model trained without this capture detects **0%** of its recon flows (`reports/model_comparison.md`).

| Metric | Fixed rule | Adaptive |
|---|---|---|
| Detection rate = recall (attack pairs) | 12/18 = 66.7% [43.7–83.7] | 17/18 = 94.4% [74.2–99.0] |
| False-positive rate (benign pairs) | 0/42 = 0.0% [0.0–8.4] | 0/42 = 0.0% [0.0–8.4] |
| Precision | 12/12 = 100.0% [75.7–100.0] | 17/17 = 100.0% [81.6–100.0] |
| Detection delay (detected scenarios) | median 10.0 s (n=1) | median 10.0 s (n=1) |
| Alerts per window (mean / max) | 0.67 / 1 | 0.94 / 1 |
| CPU per window (median / p95) | 7.4 / 9.9 ms | 28.2 / 35.0 ms |
| Memory (detector state) | none (stateless) | 22 KiB JSON |

## 4. Benign traffic aggregated behind one address (dataset Node-RED capture)

In the dataset cluster, every external client reaches the applications through the ingress gateway `100.64.0.2`. The benign Node-RED capture therefore shows one source sending about 4–5 flows/s to Node-RED, i.e. the combined load of all its users.

| Metric | Fixed rule | Adaptive |
|---|---|---|
| Detection rate = recall (attack pairs) | – | – |
| False-positive rate (benign pairs) | 155/1400 = 11.1% [9.5–12.8] | 268/1400 = 19.1% [17.2–21.3] |
| Precision | 0/155 = 0.0% [0.0–2.4] | 0/268 = 0.0% [0.0–1.4] |
| Detection delay (detected scenarios) | – | – |
| Alerts per window (mean / max) | 0.36 / 1 | 0.62 / 1 |
| CPU per window (median / p95) | 6.9 / 10.6 ms | 26.4 / 37.3 ms |
| Memory (detector state) | none (stateless) | 39 KiB JSON |

**Both behavioural detectors produce false alerts here, and the adaptive one more**, because by design it can only be more sensitive than the fixed rule. Per-source volume rules cannot tell many users behind one NAT or gateway address from one scanner. Where such an address exists, it must be listed in `behavior.ignore_sources` (and is then covered only by the ML classifier), or it needs a separate per-source baseline that is allowed above the fixed level. In this lab, clients are individual pods, so this does not occur (sessions 2 and 3).

## 5. Calibration session (session1, not an evaluation)

| Metric | Fixed rule | Adaptive | ML (per source) | Hybrid (adaptive or ML) | Controller would act |
|---|---|---|---|---|---|
| Detection rate = recall (attack pairs) | 26/27 = 96.3% [81.7–99.3] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] |
| False-positive rate (benign pairs) | 0/1168 = 0.0% [0.0–0.3] | 0/1168 = 0.0% [0.0–0.3] | 0/1168 = 0.0% [0.0–0.3] | 0/1168 = 0.0% [0.0–0.3] | 0/1168 = 0.0% [0.0–0.3] |
| Precision | 26/26 = 100.0% [87.1–100.0] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] | 27/27 = 100.0% [87.5–100.0] |
| Detection delay (detected scenarios) | median 10.1 s (n=4) | median 10.1 s (n=4) | median 10.1 s (n=4) | median 10.1 s (n=4) | median 10.1 s (n=4) |
| Alerts per window (mean / max) | 0.21 / 1 | 0.22 / 1 | 0.22 / 1 | 0.22 / 1 | 0.52 / 1 |
| CPU per window (median / p95) | 6.9 / 10.1 ms | 29.4 / 39.4 ms | see note | see note | see note |
| Memory (detector state) | none (stateless) | 59 KiB JSON | see note | see note | see note |

## Policy change made after session3 (not independently validated)

Session 3 showed that a benign client which speeds up raises repeated learned-threshold alerts. Under the earlier rule (act after 2 alert windows), the controller would have deployed decoys for it. Two changes were made after seeing this, so **session 3 is not independent evidence for them**:

* `deception.thresholds.behavior_medium_requires_ml: true`: learned-threshold alerts stay *suspicious behaviour* (shown, recorded) and act only with ML corroboration.
* ML corroboration counts only detections at ≥ `medium_confidence` (0.6), the controller's existing floor for ML evidence. The benign pod's ML false positives in session 3 had confidence 0.30–0.34; the scanners in sessions 2 and 4 have many flows at ≥ 0.6.

The detector thresholds themselves were not changed. A fresh recording would be needed to confirm the policy on unseen data.

## Overhead

* **CPU:** time to analyse one window, measured during the replay. ML inference is not included: it runs anyway for classification, and its cost is in `reports/performance.md`.
* **Memory:** the adaptive detector keeps a bounded JSON state (per-service histories capped at 1000 values, plus the flows of the last 120 s) in the SQLite `kv` table. The fixed rule is stateless.

## Conclusions

* **Slow recon.** On the held-out session the fixed rule detected 5/105 = 4.8% [2.1–10.7] of attack pairs and the adaptive detector 54/105 = 51.4% [42.0–60.8], both with 0 false positives. The adaptive detector catches medium-rate recon in every window, and low-rate and distributed recon only after its 120 s horizon has accumulated. It misses the very-low-rate scan (1 request per 6 s), which is close to the benign clients' own rate.
* **ML on the known scanner.** Per-source ML detected 94/105 = 89.5% [82.2–94.0] of attack pairs, including the slow ones, because it recognises the scanner's flows themselves rather than their volume.
* **Hybrid.** Hybrid equals ML on the known scanner. Behavioural detection matters where ML does not know the scanner (section 3) and where the per-flow model cannot be trusted (unfamiliar applications, `reports/unknown_traffic.md`).

* **Unseen scanner.** On the second lab scanner, the fixed rule detected 0/30 = 0.0% [0.0–11.4], adaptive 22/30 = 73.3% [55.6–85.8], ML 23/30 = 76.7% [59.1–88.2] and hybrid 28/30 = 93.3% [78.7–98.2]. At flow level the classifier flagged only part of this scanner's flows, at lower confidence, and labelled them *Node-RED Reconnaissance*, the only recon class it knows. The two detectors cover different windows, which is why hybrid is higher than either.
* **Changing benign traffic.** With the benign rate raised about 3×, the adaptive detector raised 35/602 = 5.8% [4.2–8.0] false alerts and the fixed rule 0/602 = 0.0% [0.0–0.6]. Under the current policy the controller would act on 0/602 = 0.0% [0.0–0.6] of these benign pairs (see the policy change above).

## Limitations

* Only flow metadata is used. HTTP paths and status codes are not visible in CICFlowMeter records.
* Recon slower than normal clients' request rates cannot be separated by volume.
* Many users behind one NAT or gateway address look like one scanner (section 4).
* The adaptive detector assumes its warm-up traffic is benign. Its fixed-level cap limits how far a learned threshold can move.
* All attackers are the lab's own generators (HTTP requests only). No other scanner software was run.
