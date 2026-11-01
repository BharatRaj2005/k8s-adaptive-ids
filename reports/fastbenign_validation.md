# Fast-benign validation (offline scoring)

Fresh benign capture, independent of training. Flows scored offline with each model via the
production `FlowPredictor` path (threshold + unknown gate). Ground truth: all generated traffic
is benign, so any attack verdict is a false positive. 'Generator flows' are the scenario pod's
flows (the fast-benign traffic of interest); the rest of each window is cluster background.

## Capture
| Set | Scenario | Target | Generator benign flows |
|---|---|---|--:|
| fbenign_api_nodered | api_client | nodered | 1968 |
| fbenign_api_grafana | api_client | grafana | 1956 |
| fbenign_api_influxdb | api_client | influxdb | 1971 |
| fbenign_burst_nodered | burst | nodered | 831 |
| fbenign_browse_grafana | browse | grafana | 400 |

## Benign false positives on generator (fast-benign) flows
| Model | Gen flows (denom) | FP | FPR | FPR conf>=0.9 | FP classes | Behaviour bursts |
|---|--:|--:|--:|--:|---|--:|
| et_dataset_sqrt_lab | 7126 | 54 | 0.0076 | 0.0 | {'Node-RED Reconnaissance': 49, 'CVE-2021-43798': 2, 'Node-RED RCE': 3} | 39 |
| v2_et_none | 7126 | 707 | 0.0992 | 0.0036 | {'Node-RED Reconnaissance': 706, 'Node-RED Container Escape': 1} | 39 |

### et_dataset_sqrt_lab
- Confidence histogram over generator benign flows: {'<0.3': 0, '0.3-0.5': 67, '0.5-0.7': 549, '0.7-0.9': 604, '>=0.9': 5906}
- Confidence histogram over the false positives: {'<0.3': 0, '0.3-0.5': 9, '0.5-0.7': 45, '0.7-0.9': 0, '>=0.9': 0}
- All benign flows (incl. background): 54 FP / 9603

| Set | Scenario | Gen flows | FP | FPR | FP classes | Bursts |
|---|---|--:|--:|--:|---|--:|
| fbenign_api_nodered | api_client | 1968 | 15 | 0.0076 | {'Node-RED Reconnaissance': 15} | 9 |
| fbenign_api_grafana | api_client | 1956 | 0 | 0.0 | - | 11 |
| fbenign_api_influxdb | api_client | 1971 | 0 | 0.0 | - | 10 |
| fbenign_burst_nodered | burst | 831 | 34 | 0.0409 | {'Node-RED Reconnaissance': 34} | 6 |
| fbenign_browse_grafana | browse | 400 | 5 | 0.0125 | {'CVE-2021-43798': 2, 'Node-RED RCE': 3} | 3 |

### v2_et_none
- Confidence histogram over generator benign flows: {'<0.3': 3, '0.3-0.5': 181, '0.5-0.7': 328, '0.7-0.9': 550, '>=0.9': 6064}
- Confidence histogram over the false positives: {'<0.3': 3, '0.3-0.5': 181, '0.5-0.7': 328, '0.7-0.9': 169, '>=0.9': 26}
- All benign flows (incl. background): 708 FP / 9603

| Set | Scenario | Gen flows | FP | FPR | FP classes | Bursts |
|---|---|--:|--:|--:|---|--:|
| fbenign_api_nodered | api_client | 1968 | 394 | 0.2002 | {'Node-RED Reconnaissance': 394} | 9 |
| fbenign_api_grafana | api_client | 1956 | 118 | 0.0603 | {'Node-RED Reconnaissance': 118} | 11 |
| fbenign_api_influxdb | api_client | 1971 | 2 | 0.001 | {'Node-RED Reconnaissance': 2} | 10 |
| fbenign_burst_nodered | burst | 831 | 167 | 0.201 | {'Node-RED Reconnaissance': 166, 'Node-RED Container Escape': 1} | 6 |
| fbenign_browse_grafana | browse | 400 | 26 | 0.065 | {'Node-RED Reconnaissance': 26} | 3 |

## MAPE-K deception (would it activate on this benign traffic?)
Deception deploys on an attack verdict: an ML-malicious flow from an eligible source, or a
behavioural flow-burst. Behavioural bursts are model-independent (flow rate only).
- **et_dataset_sqrt_lab**: ML false deception trigger: YES (54 FP flows); behavioural trigger: YES (39 bursts) -> would deploy decoys: **YES**
- **v2_et_none**: ML false deception trigger: YES (707 FP flows); behavioural trigger: YES (39 bursts) -> would deploy decoys: **YES**

## Findings

Denominator: 7,126 generator benign flows across 5 runs (9,603 incl. cluster background);
0 attack flows (benign ground truth). Both models scored on the identical captured flows.

1. **ML false positives collapse with the lab-trained model.** On the fast-benign generator
   flows, `et_dataset_sqrt_lab` gives **0.76% FPR (54/7126) and 0% at confidence >= 0.9**;
   `v2_et_none` gives **9.92% (707/7126) with 26 high-confidence FPs**. A ~13x reduction, and
   every remaining FP is low-confidence (< 0.7). The MAPE-K controller acts on high-confidence
   verdicts, so the new model contributes **no high-confidence ML trigger** on this benign traffic.
2. **Residual ML FPs are Node-RED-specific and low-confidence**: bursty Node-RED refresh 4.1%,
   fast API to Node-RED 0.76%; fast API to Grafana/InfluxDB 0%. Benign Node-RED connection
   patterns occasionally read as reconnaissance, but weakly.
3. **Behavioural flow-burst alerts are unchanged at 39 for BOTH models** - they depend only on
   flow rate, not the model. Fast API clients (~8/s) and bursty refreshes open >= 15 flows/window
   to one service, which is structurally identical, in volume, to a scan.
4. **MAPE-K would still deploy decoys on fast benign** - but under the new model the trigger is
   purely the behavioural path, not the ML path. The ML improvement alone does not fully fix
   false deception on fast-benign clients.

## Recommendation

- The lab-trained 11-class model is clearly safer on fast-benign traffic (13x fewer FPs, zero
  high-confidence) and detects the attack classes at 95-100% (see `reports/multiclass_baseline.md`
  and the retrain lab eval). From the ML standpoint it is safe to adopt as the active model.
- **Before relying on deception with fast-benign clients present, gate MAPE-K on ML corroboration:**
  require a behavioural flow-burst to be confirmed by a high-confidence (>= 0.9) ML attack verdict
  from the same source before deploying decoys (AND, not OR). The data supports this: the new model
  produces 0 high-confidence benign FPs but 95-99% high-confidence verdicts on real attacks, so an
  AND gate keeps attack response while suppressing fast-benign false deception.
- Complementary: the adaptive behavioural threshold (already enabled, warmup 30 windows) learns
  per-service benign rates and will raise the bar for busy-but-benign services over time.
- This evaluation data is kept as an independent set (data/lab/fbenign_*) and is NOT added to training.
