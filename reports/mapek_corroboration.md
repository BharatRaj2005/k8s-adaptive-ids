# Active model switch + MAPE-K ML-corroboration policy

2026-11-01. Active model changed to the 11-class lab model and deception gated on ML corroboration
so behavioural alerts alone cannot deploy decoys. Architecture, RBAC and NetworkPolicies unchanged.

## 1. Active model

- `config/settings.yaml` active_model: `v2_et_none` -> `et_dataset_sqrt_lab` (settings backed up to
  `config/settings.yaml.bak.<ts>`). `fallback_model: v2_et_none` added and honoured by
  `FlowPredictor.from_config` (used only if the active model cannot be loaded).
- Built `models/et_dataset_sqrt_lab/service_profile.json` so the unknown-traffic gate applies.
- Backend restarted; `/api/health` reports model=et_dataset_sqrt_lab, model_available=true, no fallback.

## 2. MAPE-K corroboration

- New `thresholds.behavior_requires_ml: true`; `medium_confidence` 0.6 -> 0.7.
- `behaviour_actionable()` (src/deception/controller.py): a flow burst (fixed-rule or learned) deploys
  a decoy only with ML corroboration from the same source - a high-confidence detection (>= 0.90), or
  repeated medium-confidence detections (>= 3 at >= 0.70). Behavioural evidence alone never deploys.
- A single medium-confidence ML detection no longer acts even with a burst (fast/bursty benign produces
  exactly that); medium confidence must be repeated.
- Non-actionable behaviour is recorded as `await_evidence` (shown in the UI), not dropped.

## 3. Validation (offline, active model + policy, independent lab sets)

Per source: ML high/medium-confidence malicious counts + behavioural burst, fed to the real controller
decision functions. Benign sets must not deploy; scanner/attack sets should.

| Set | kind | gen flows | ML>=0.9 | ML>=0.6 | burst | decoy deploys |
|---|---|--:|--:|--:|:--:|:--:|
| fbenign_api_nodered | benign | 1968 | 0 | 0 | yes | no |
| fbenign_api_grafana | benign | 1956 | 0 | 0 | yes | no |
| fbenign_api_influxdb | benign | 1971 | 0 | 0 | yes | no |
| fbenign_burst_nodered | benign | 831 | 0 | 0 | yes | no |
| fbenign_browse_grafana | benign | 400 | 0 | 0 | yes | no |
| recon_run1 (original) | scanner | 303 | 303 | 303 | yes | YES |
| recon_run2 (original) | scanner | 202 | 139 | 183 | yes | YES |
| recon_threaded_nodered (unseen scanner) | scanner | 300 | 0 | - | yes | YES (repeated medium ML) |
| recon_slow_nodered (slow) | scanner | 49 | 0 | 0 | no | no |
| recon_seq_grafana (unseen app) | scanner | 199 | 0 | 0 | yes | no |
| attack_nodered_rce_eval | attack | 99 | 98 | 98 | yes | YES |
| attack_grafana_traversal_eval | attack | 120 | 114 | 117 | yes | YES |
| attack_influx_authbypass_eval | attack | 99 | 97 | 99 | yes | YES |

**False decoy activations (benign): 0 / 5. Attack classes: 3 / 3. Scanners: 3 / 5.**

Policy sweep (benign false / scanner / attack), chosen row in bold:
- high 0.90, med 0.60, repeat 3 -> 1/5, 3/5, 3/3  (bursty benign triggers)
- **high 0.90, med 0.70, repeat 3 -> 0/5, 3/5, 3/3  (shipped)**
- high 0.90, med 0.70, repeat 5 -> 0/5, 3/5, 3/3
- high 0.90, med 0.80, repeat 3 -> 0/5, 2/5, 3/3  (loses a scanner)

## 4. The unseen-scanner trade-off (important)

Requiring ML corroboration drops two scanner cases that have **no ML signal**:
- **recon_seq_grafana** (reconnaissance of Grafana, an application the model was not trained to
  recognise as recon): it bursts but produces zero ML detections, so it is indistinguishable, by ML,
  from bursty benign. Under the old behaviour-alone policy its burst would have deployed a decoy; under
  the corroboration policy it does not. **This is a real reduction in unseen-application recon detection.**
- **recon_slow_nodered** (slow HEAD crawl): no ML and below the fixed flow-burst rule. NOTE: this offline
  evaluation uses only the fixed-rule flow burst; the live slow_scan / adaptive_rate detectors are not
  modelled here, so slow recon may still be caught live - to be confirmed.

The unseen-*technique* scanner (threaded_parallel) IS still caught, via repeated medium-confidence ML.

## 5. Recommendation (applied 2026-11-01 - see section 7)

To honour "do not compromise unseen-scanner detection", give the model ML signal on the other apps:
capture lab recon against Grafana and InfluxDB into TRAINING sets (separate from the eval sets here)
and retrain, so Grafana/InfluxDB recon gains ML evidence and the corroboration gate keeps catching it.
Separately, confirm the live slow_scan/adaptive detectors on slow recon. Until then, the shipped policy
trades a small loss of unseen-application recon detection for zero benign false decoy activations.

## 6. Visibility and checks

- Behavioural alerts are always recorded in `behavior_alerts` (surfaced by /api/alerts and the overview);
  non-actionable ones also appear as `await_evidence` decisions. Unknown (`status=unknown`) and simulated
  (`simulated=1`) flows are counted separately from genuine ML detections in every query.
- Tests: 187 passed (full suite, incl. the live-cluster decoy lifecycle test). Deception tests updated to
  the new policy, plus a new test that a flow burst alone never deploys.

## 7. Closing the unseen-application recon gap (2026-11-01, follow-up)

Section 5 applied. Active model is now **`et_dataset_sqrt_lab_v6b`** (v3, then v5 after the slow-recon
follow-up in 7.6, then v6b after the class-1 work in section 8) (settings backed up to
`config/settings.yaml.bak.<ts>`; `fallback_model: v2_et_none` unchanged; service profile built;
`/api/health` reports model=et_dataset_sqrt_lab_v6b, no fallback). The MAPE-K policy is unchanged.

### 7.1 New lab sets (all real captured simulator traffic, separate runs per set)

| Set | Use | Scenario | Labelled flows |
|---|---|---|--:|
| recon_grafana_train | train | recon/sequential -> Grafana | 193 recon / 275 benign |
| recon_influx_train | train | recon/sequential -> InfluxDB | 199 / 296 |
| fbenign_api_{nodered,grafana,influxdb}_train | train | benign/api_client (fast, ~8 req/s) | all benign |
| fbenign_burst_grafana_train | train | benign/burst | all benign |
| fbenign_browse_{grafana,nodered}_train | train | benign/browse | all benign |
| recon_seq_influx | **eval** | recon/sequential -> InfluxDB | 198 / 297 |
| recon_shuffled_grafana | **eval** | recon/shuffled (technique not in any training set) -> Grafana | 198 / 363 |
| fbenign_keepalive_grafana | **eval** | benign/keepalive (behaviour type in no training set) | all benign |
| fbenign_poller_influxdb | **eval** | benign/poller (behaviour type in no training set) | all benign |

Capture scripts: `scripts/capture_recon_labsets.py`, `scripts/capture_fastbenign_labsets.py`
(the latter now merges `data/lab/fastbenign_meta.json` instead of overwriting it on partial runs).
All original eval sets (`fbenign_*` without `_train`, `recon_seq_grafana`, `recon_threaded_nodered`,
`recon_slow_nodered`, `recon_run2`, `attack_*_eval`) remain held out.

### 7.2 Iterations (all three models kept in `models/` and the registry)

Evaluated with `scripts/eval_mapek_policy.py <model>` (shipped policy: high 0.90, med 0.70, repeat 3).

| Model | Added to training | Benign false decoys | Scanner sets -> decoy | Attack sets -> decoy |
|---|---|--:|--:|--:|
| et_dataset_sqrt_lab (previous active) | - | 0 / 7 | 3 / 7 | 3 / 3 |
| et_dataset_sqrt_lab_recon | Grafana/InfluxDB recon only | **6 / 7** | 6 / 7 | 3 / 3 |
| et_dataset_sqrt_lab_v2 | + fast API / burst benign | 1 / 7 (browse_grafana) | 6 / 7 | 3 / 3 |
| **et_dataset_sqrt_lab_v3** | + browse benign | **0 / 7** | **6 / 7** | **3 / 3** |

Recon-only training (as originally proposed) **broke the benign result**: with no fast benign
Grafana/InfluxDB examples in training, the model learned "fast lab-pod traffic to these apps = recon"
and every fast-benign set produced high-confidence recon detections. Adding fast/bursty/browsing benign
counterexamples from separate runs restored 0 false activations. Note the iteration risk: v2 -> v3 was
driven by an eval-set failure (browse). To check that v3 is not just patched to the visible failures,
two benign sets of behaviour types absent from all training (keep-alive, poller) were captured after v2
and held out; v3 produces 0 malicious flows on both. v3 is also 0 / 7 benign across the whole policy
sweep (incl. med 0.60), where the previous model was 1 / 7 at med 0.60.

Per-set v3 evidence (generator/attacker pod flows only):

| Set | kind | ML >= 0.9 | ML >= 0.7 | burst | decoy |
|---|---|--:|--:|:--:|:--:|
| recon_seq_grafana (was the gap) | scanner | 85 | 146 | yes | **YES** (was no) |
| recon_seq_influx | scanner | 159 | 182 | yes | YES |
| recon_shuffled_grafana (unseen technique) | scanner | 14 | 41 | yes | YES |
| recon_threaded_nodered | scanner | 0 | 6 | yes | YES (repeated medium ML) |
| recon_slow_nodered | scanner | 0 | 0 | no | no |
| fbenign_* (7 sets) | benign | 0 | 0 | 5 of 7 | no |

### 7.3 Costs / regressions (honest)

- Per-flow recon recall on Node-RED threaded scanning fell (0.97 -> 0.56 flow-level) and on shuffled
  Grafana it is 0.53; both still deploy via repeated ML corroboration, but with less margin.
- Dataset test split essentially unchanged: accuracy 0.9667 (0.9669), macro-F1 0.2985 (0.3083; the drop is
  in classes with 8-14 test rows - CVE-2022-23648 / CVE-2019-5736 - i.e. noise), benign holdout FPR 0.369 %
  (0.352 %). Lab attack eval sets unchanged (100 % detected, >= 94 % at conf >= 0.9).

### 7.4 Slow recon, live (dry run)

`scripts/dryrun_mapek_run.py <run_id>` feeds a simulator run's live detections and behavioural alerts
(incl. the slow_scan / adaptive detectors the offline eval does not model) to the real controller
analyze() + plan() with a read-only database; nothing is executed. Slow scanner (head_crawler, 50 HEAD
requests over ~180 s) with v3 active:

| Run | Live slow_scan alerts | ML malicious (v3) | Decision |
|---|--:|--:|---|
| sim-20261101-064509-08ae -> Node-RED | 5 | 0 | **await_evidence - no decoy** |
| sim-20261101-064817-9b83 -> Grafana | 7 | 26 (2 >= 0.9) | deploy (ML high + slow_scan corroborated) |

So slow recon **does need something**: on Node-RED the live slow_scan detector fires but the ML gate
holds it. Letting slow_scan act alone is not safe on current evidence: benign `poller` runs raised a
slow_scan alert in 2 / 2 simulator runs (another 120 slow_scan alerts on 2026-10-31 come from pods with
no ground-truth record and are not counted either way). Addressed in 7.6 with a slow-recon training set.

### 7.5 Checks

Full test suite with v5 active and the backend up: 188 passed, 0 skipped.

### 7.6 Slow recon on Node-RED (v4 -> v5, active)

New sets: `recon_slow_nodered_train` (slow HEAD crawl, 300 s, 90 recon flows) paired with benign
counterexamples `fbenign_poller_nodered_train` and `fbenign_burst_nodered_train` (separate runs); held out:
`recon_slow_influx` (slow recon, other app, 50 recon flows) and `fbenign_poller_nodered` (poller on the
same app as the slow-recon training set - the most likely confuser).

| Model | Benign false decoys | Scanner sets -> decoy | Attack sets -> decoy | med 0.60 sweep (benign) |
|---|--:|--:|--:|--:|
| et_dataset_sqrt_lab_v3 | 0 / 8 | 7 / 8 (misses recon_slow_nodered) | 3 / 3 | 0 / 8 |
| et_dataset_sqrt_lab_v4 (+ slow recon, poller) | 1 / 8 (fbenign_burst_nodered, 7 recon dets, max 0.77) | 8 / 8 | 3 / 3 | 2 / 8 |
| **et_dataset_sqrt_lab_v5 (+ burst Node-RED benign)** | **0 / 8** | **8 / 8** | **3 / 3** | 1 / 8 |

v4's false activation could also have been removed by raising medium_confidence to 0.80 (0 / 8, 8 / 8),
but that would tune the policy on the eval sets and leave threaded recon resting on 2 high-confidence
flows, so the policy was left unchanged and the missing counterexample added instead. v5 has slightly
less benign margin than v3 at the loosest sweep setting (1 / 8 at med 0.60; shipped is 0.70).

Because v4 -> v5 was again driven by an eval-set failure, v5 was checked on **fresh live runs** never used
for any decision (simulator, v5 active, dry-run controller on the live detections/alerts):

| Fresh live run | ML malicious (v5) | Behaviour alerts | Decision |
|---|--:|---|---|
| recon/slow -> Node-RED (sim-20261101-072858-a3b5) | 47 (max 1.00) | 6 slow_scan | **deploy** (was await_evidence with v3) |
| benign/burst -> Node-RED (sim-20261101-073207-be53) | 1 (0.79) | 7 flow_burst, 2 adaptive_rate, 1 slow_scan | await_evidence - no decoy (1/3 medium) |
| benign/poller -> Node-RED (sim-20261101-073405-1c24) | 0 | 9 adaptive_rate, 1 slow_scan | await_evidence - no decoy |

The benign runs raised 10 behavioural alerts each; only the ML-corroboration gate keeps them from
deploying, which is why the gate stays. Dataset split for v5: accuracy 0.9669, macro-F1 0.3028, benign
holdout FPR 0.352 %. Lab attack eval sets: 100 % detected.

## 8. Attack classes 3/5/6 (more, more-diverse samples) and class 1 (Grafana SSRF)

New lab sets (real simulator traffic, marker requests only; request paths are the generator's fixed
safety-reviewed sets, so diversity comes from rate, duration and each run's random seed):
- train, rates not used before (the original attack train sets ran at 5 req/s):
  `attack_{nodered_rce,grafana_traversal,influx_authbypass}_train_r2` (2 req/s, ~237 attack flows each) and
  `_train_r9` (9 req/s, ~335 each);
- held out at a rate in no training set: `attack_*_eval_r1` (1 req/s, 119 attack flows each);
- class 1: `attack_grafana_ssrf_train` (5 req/s, 118 flows), `attack_grafana_ssrf_train_r2` (2 req/s, 237),
  held-out `attack_grafana_ssrf_eval` (5 req/s, 98).

New `scripts/lab_class_report.py <model>...` pools all 24 held-out lab sets (23 416 flows; attacker flows
carry the set class, the rest benign), scores them as in live operation and reports per-class P/R/F1, so
cross-class confusion shows up as lost precision. Ablation (all share v5's training sets):

| Model | added | SSRF (1) F1 | RCE (3) F1 | traversal (5) F1 | InfluxDB (6) F1 | recon F1 | benign false / scanner / attack decoys | med 0.60 benign |
|---|---|--:|--:|--:|--:|--:|---|--:|
| v5 | - | 0.000 | 1.000 | 0.947 | 0.998 | 0.893 | 0/8, 8/8, 6/7 | 1/8 |
| v6a | rate sets | 0.000 | 1.000 | 0.934 | 1.000 | 0.872 | 0/8, 8/8, 6/7 | 1/8 |
| v6 | rate + SSRF sets | 1.000 | 1.000 | 1.000 | 1.000 | 0.893 | 0/8, 8/8, 7/7 | 1/8 |
| **v6b (active)** | SSRF sets | **1.000** | **1.000** | **1.000** | **0.998** | **0.897** | **0/8, 8/8, 7/7** | **0/8** |

Findings:
- **Item 3 (more/diverse samples for 3/5/6): no measurable gain - nothing to lift in the lab.** v5, trained only
  at 5 req/s, already detects the 1 req/s held-out runs at 100 % / 100 % / 99.2 %. The extra rate sets (v6a)
  changed nothing for 3/5/6 and cost some recon recall (0.824 -> 0.793), so they are not in the active model.
  On the published-dataset test split, F1 for 3/5/6 is unchanged by any lab data (v5 0.042 / 0.286 / 0.565,
  v6b 0.041 / 0.267 / 0.562 on 42 / 9 / 48 test rows - noise): those rows are real exploit flows that overlap
  benign at the flow level, and simulated attack-shaped traffic does not teach the model about them.
- **Item 4 (class 1): separable in the lab once trained.** Without SSRF training, the SSRF runs were partly
  labelled as Grafana traversal (51 / 98 flows malicious, all < 0.6 confidence, no decoy) - which was also the
  hidden cause of traversal's 0.898 precision in v5. With the two SSRF training sets, the held-out SSRF run is
  98 / 98 correct at confidence 1.00 and traversal precision returns to 1.000. Dataset-split class 1 stays at
  0 (14 test rows): this is separability of the *simulated* SSRF shape, not detection of the real exploit.
- v6b over v6: same shipped-policy result, more benign margin (0/8 at med 0.60), and the rate sets measurably
  add nothing.

Fresh live runs (v6b active, dry-run controller; runs used for no decision):

| Run | ML malicious | Decision |
|---|---|---|
| attack/grafana_ssrf (sim-20261101-081342-a3dc) | 119 x CVE-2020-13379 (1.00) | deploy grafana decoy |
| attack/grafana_traversal (sim-20261101-081440-a0fe) | 199 x CVE-2021-43798 (1.00) - not confused with SSRF | deploy grafana decoy |
| benign/browse -> Grafana (sim-20261101-081549-e7e4) | 1 (0.64, low) | monitor / await_evidence - no decoy |

Known limit: no benign profile requests Grafana `/avatar/...` (the SSRF endpoint; a real Grafana UI loads
avatars), so legitimate avatar loads are untested against the SSRF class. Covering it needs a benign avatar
path in the generator (a reviewed ConfigMap change) - not done.

Dataset split (v6b): accuracy 0.9669, macro-F1 0.3160, benign holdout FPR 0.335 %. Tests: 188 passed.

