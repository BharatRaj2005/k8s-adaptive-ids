# Live validation: Live Security Monitoring and Attack Simulator

Run on 2026-10-31, 17:39–18:08 UTC, on the K3s lab (single node, v1.36.5+k3s1), branch `frontend-monitoring`.
Every simulation was started from the dashboard (*Live Security Monitoring* → **Attack Simulator** → confirm →
**START SIMULATION**). Headless Chrome operated the page through the DevTools protocol and clicked the real
widgets; no run was started through the API directly. Each run was followed with `scripts/watch_simulation.py`.
Active model `v2_et_none` (unchanged). The deception controller was enabled throughout.

All figures are counted from `data/ids.sqlite`, the saved generator logs (`data/simulations/`) and `kubectl`
output. "HTTP flows" are the generator pod's flows to the target application's port; "DNS" are its lookups. Both are
tagged with the run id (traffic origin). Only the classifier's verdicts decide what counts as an attack.

## Results

| Test | Run | Profile → target | Outcome | Requests | HTTP flows → recon verdicts | DNS flows (attack verdicts) | Behavioural alerts | Cleanup |
|---|---|---|---|---|---|---|---|---|
| 1 Recon | `sim-…173945-589e` | Sequential scanner → Node-RED | completed | 288 | 282 → **282 (100 %)** | 1,127 (0) | 8 high | ✓ Job + Pod deleted, verified |
| 2 Benign | `sim-…174402-831d` | Browsing user → Node-RED | completed | 80 | 79 → **42 (53 %)** false positives | 316 (0) | 3 high, 2 medium | ✓ |
| 2 Benign | `sim-…174626-bb5a` | High-volume API client (8 req/s) → Node-RED | completed | 400 | 395 → **395 (100 %)** false positives | 1,574 (0) | 10 high | ✓ |
| 2 Benign | `sim-…174818-2ddf` | Health/metrics poller (1 req/s) → Node-RED | completed | 89 | 89 → **3 (3.4 %)** false positives | 356 (0) | 10 medium | ✓ |
| 3 Cancel | `sim-…175051-3554` | Shuffled jitter → Grafana | cancelled | 80 logged | 107 → 45 | 428 (0) | 3 high | ✓ (pod lived ~30 s, see fix 2) |
| 3 Cancel | `sim-…175414-4ad2` | Shuffled jitter → Grafana | cancelled | 200 | 200 → 86 | 798 (0) | 6 high | ✓ (pod lived ~30 s; the cancel landed after traffic ended) |
| 3 Cancel (final) | `sim-…175656-db86` | Shuffled jitter → Grafana | cancelled | 101 | 100 → 44 | 399 (0) | 2 high, 2 medium | ✓ traffic stopped ≈1 s after cancel |
| 4 Interruption | `sim-…175948-42fc` | Sequential scanner → InfluxDB | interrupted | – (see fix 3) | 25 → 20 | 100 (0) | 1 high | ✓ |
| 4 Interruption (final) | `sim-…180230-e248` | Sequential scanner → InfluxDB | interrupted | 165 | 155 → 88 | 618 (0) | 5 high, 1 medium | ✓ |

### Test 1: live reconnaissance (pass)
* Monitoring was stopped, so the run **started its own capture** (`capture_owned=1`) and stopped it after
  the last window. 10 windows, all `classified`, 0 pending.
* All 10 stages were reached in order: requested 17:39:45 → Job 17:39:47 → pod 17:39:49 (10.42.0.84) → traffic
  until 17:40:51 → final window classified 17:40:59 → results stored 17:40:59 → **cleaned up 17:41:01**.
* All 282 HTTP flows to Node-RED were classified *Node-RED Reconnaissance*. 8 fixed-rule flow bursts (24–48 flows
  per window, 2.6–4.8 flows/s).
* MAPE-K deployed `http-recon` and `nodered` and scaled `http-recon` on repeated evidence. A single
  recon verdict on the benign generator (10.42.0.46) was only `monitor`ed.
* The live feed showed the run's flows as each window was processed (screenshots during and after the run).
  The run panel displayed the generator pod, requests, packets (14,778 in 9 windows), flows (2,051; 1,409
  from the generator pod), 282 detected attacks, 8 alerts and the cleanup result.

### Test 2: benign traffic (lifecycle pass; classification **fails** for two of three profiles)
* Monitoring had been started from the toolbar first. All three runs **attached** to it
  (`capture_owned=0`), and the capture kept running after every run.
* **Classification of benign traffic by the active model and the burst rule:**
  * *Browsing user*: 42 / 79 page and asset loads (`GET /theme`, `/icons`, `/locales/editor`, `HEAD /`, all 200 OK)
    were classified as reconnaissance (mean confidence 0.69). 3 fixed-rule bursts at 15–17 flows / 10 s. The
    rule fires at ≥ 15 flows and ≥ 1 flow/s, and a page with assets alone exceeds that.
  * *High-volume API client*: every one of 395 valid API requests was classified as reconnaissance, with 10 bursts.
  * *Health/metrics poller*: 86 / 89 benign. Its 10 learned-threshold (medium) alerts led only to `await_evidence`,
    and the 3 low-confidence verdicts only to `monitor`.
* **Deception:** no *new* decoy was deployed during Test 2 only because Test 1's decoys were still active. The
  controller refreshed their TTL 12 and 18 times on the browsing and API-client runs; with no decoys active it would
  have deployed them. The poller caused no deception action.
* This is the per-flow limitation already recorded in `reports/model_comparison.md`. `v2_et_none` learned benign
  Node-RED traffic from one low-rate generator with 10 endpoints, so fast new-connection HTTP traffic to Node-RED
  looks like reconnaissance. The active model was not changed (instruction). The dataset in
  `reports/balanced_dataset_analysis.md` exists to retrain for exactly this.

### Test 3: cancellation (pass after two fixes)
* Final run: cancelled through the panel's **Cancel simulation** popover about 25 s in. The last generator request
  was at 17:57:28.1 and the log has no `end` event (the generator was stopped, not finished). Cleanup was verified
  at 17:57:37.
* Logs preserved: 304 events (`data/simulations/sim-20261031-175656-db86.log.jsonl`, also served by
  `GET /api/simulations/{id}/logs`). **All 100 captured HTTP flows match a logged connection** (local port).
* The windows captured before the cancel were classified and stored (44 recon verdicts, 4 alerts). The run is
  `cancelled` with "cancelled by the user".

### Test 4: backend interruption (pass after one fix)
* The backend was killed with `SIGKILL` 24 s into the final run, then restarted 10 s later with `./start.sh`.
  While it was down, the Job and the run's own capture kept running.
* Recovery at start-up (`simulation recovery: {'interrupted': ['sim-20261031-180230-e248'], 'orphans': [], 'errors': []}`):
  saved the log up to the last event (18:03:11), deleted the Job, stopped the capture the run had started (only
  that PID), tagged **all** generator-pod flows (0 untagged afterwards), stored the results (165 requests, 773 flows,
  88 recon verdicts, 6 alerts) and verified that nothing was left. Run status: `interrupted`.
* **Unrelated resources:** a snapshot of every Deployment, ReplicaSet, Service, Pod, ConfigMap, NetworkPolicy,
  ServiceAccount, Role and RoleBinding in `target-apps`, `ids-traffic` and `ids-deception` (uid, resourceVersion,
  restart count) taken just before the run equals the one taken after recovery, apart from the run's own Job and Pod.

### Test 5: the 13-step demonstration (13 / 13 pass, `reports/deception_test_report.md`)
* Benign phase: 3 windows, 290 flows, 0 predicted malicious, 0 deploy/scale decisions.
* Reconnaissance (demo recon Job, 10.42.0.99): 9 flow-burst alerts (max 49 flows/window); 301 of 1,505 attacker
  flows predicted malicious (the HTTP flows; the rest are its DNS lookups).
* MAPE-K chose `nodered` and `http-recon` (confidence 1.00, ML and behavioural evidence from the same source);
  both were healthy after 15.4–15.5 s.
* 52 decoy interactions from the decoy-probe Job, all linked to a decision.
* The simulated CVE-2019-5736 event deployed `container-env`. Its decision reason begins "SIMULATED test event",
  the decoy is flagged `simulated=1`, and no simulated row exists in `detections`.
* Step 13: all managed decoys were removed, with no managed resources left. The demo's own completed recon and
  decoy-probe Jobs (TTL 1 h) were then deleted by name.

## Defects found by these tests and fixed

| # | Found in | Defect | Fix (re-verified live) |
|---|---|---|---|
| 1 | Test 1 | While a run was active, its flows showed as *Observed*: they were tagged only at the end, and the browser's incremental buffer never re-reads rows it already holds. | The backend tags generator-pod flows every second during the run, and the feed also derives the origin from the run's pod IP and time span. |
| 2 | Test 3 | Cancel did not stop the traffic for ~30 s: the generator runs as PID 1 without a SIGTERM handler, so it ignored SIGTERM until the grace period ended. The log was also read before deletion, so 27 of 107 flows lacked a logged connection. | Simulator Jobs set `terminationGracePeriodSeconds: 1` (the generator flushes every log line). Logs are snapshotted during the run and drained until the pod is gone. Final cancel run: traffic stopped ≈ 1 s after the cancel, and 100 / 100 flows matched. |
| 3 | Test 4 | Recovery deleted the Job without collecting the final log and did not tag flows from windows processed while the backend was down (451 untagged). | Recovery now saves and drains the log, stops the run's own capture (which processes its remaining windows), records the processing stages, tags all generator flows and stores the results before verifying cleanup. Final interruption run: 0 untagged flows. |
| 4 | final screenshot | The interrupted run's tracker showed ✕ *PCAP captured* although its windows had been processed. | Recovery records the capture/conversion/classification/behavioural stages when the run's windows exist (unit-tested; no extra live run). |

The records of runs made before a fix are kept as they were produced. For example, `sim-…175948-42fc` has no request
count because the pre-fix recovery never read its log; its partial log file is in `data/simulations/`.

## Final checks
1. No simulator Jobs or Pods, and no other Jobs, in `ids-traffic`. No decoys in `ids-deception`.
2. `traffic-benign`: same Pod, uid, resourceVersion and restart count as before Test 1.
3. `target-apps`: 17 objects identical to the snapshot before Test 1 (uid, resourceVersion, restarts).
4. Captures: 569 windows, all `classified`. No pending PCAP files. The capture service is stopped.
5. 9 simulation records are available through `/api/simulations`, each with a verified cleanup result. 8 of 9 runs
   have their generator log registered; the ninth is the pre-fix interrupted run above.
6. Automated tests: **181 passed, 0 failed, 0 skipped** (`.venv/bin/python -m pytest -q`, 151.7 s, including the
   live-cluster decoy lifecycle test).
7. Dashboard screenshots before, during and after runs, and the API responses above, were inspected.

## Remaining limitations
* **Benign false positives (detection, not simulator).** Benign browsing at ≈ 1.4 req/s and API clients at 8 req/s
  are flagged as reconnaissance by `v2_et_none`, and their flow rate exceeds the fixed burst rule, so with deception
  enabled such clients would cause decoy actions. This needs the retraining planned on the generated dataset.
* **Reconnaissance recall outside Node-RED** with the current model: Grafana 42–45 %, InfluxDB 57 % of HTTP flows
  (Node-RED 100 %). The class is the dataset's *Node-RED Reconnaissance* and was trained on Node-RED scans only.
* The ground-truth tagging marks the generator pod's flows of the run's windows; DNS lookups are tagged as lab
  traffic but not counted as attacks. A window shared with other traffic contributes its full packet count to the
  run's *Captured packets*.
* One active run at a time. Runs are window-based like the rest of the pipeline: results arrive about one window
  plus ~1 s after the last request.
* If the backend is down while a run uses an *attached* (user-started) capture that keeps running, windows
  processed after recovery are not tagged with the run (recorded in the run's error text).
