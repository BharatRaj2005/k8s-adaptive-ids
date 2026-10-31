# Performance Measurements

Generated 2026-10-31 06:10 UTC by `scripts/measure_performance.py` on this machine (12 CPUs, 7.6 GiB RAM, WSL2). All values are measured; unavailable sources are stated as such.

## Model (offline evaluation, active model)

- Model: `v2_et_none` · accuracy 0.9982 · macro F1 0.7290 · weighted F1 0.9982 (details: `reports/model_evaluation.md`)
- Single-flow prediction latency (preprocessing + inference): median 27.2 ms, p95 42.2 ms (200 samples)
- Batch prediction: 20.3 µs per flow (16,149 flows in 328 ms)

## Live pipeline (classified capture windows)

- Capture window length: n=380 · median 10.1 s · mean 9.8 · p95 10.1 · max 10.1
- Feature extraction (CICFlowMeter, PCAP → validated CSV): n=380 · median 0.88 s · mean 0.83 · p95 1.08 · max 1.54
- Flows per window: n=380 · median 65 flows · mean 92 · p95 272 · max 525
- Prediction per window: n=380 · median 45.8 ms · mean 50.0 · p95 81.0 · max 183.9
- End-to-end (window closed → detections stored): n=380 · median 1.05 s · mean 1.00 · p95 1.30 · max 2.00
- Detection delay therefore ≈ window length (5–30 s, adaptive) + the end-to-end figure above.

## Deception

- Decoy deployment time (create → first ready replica): n=5 · median 15.3 s · mean 14.9 · p95 15.4 · max 15.4
- Last MAPE-K cycle: 34 ms

## Resource usage

Host processes (psutil, CPU sampled over 1 s):

| Process | PID | CPU % | RSS MB |
|---|---|---|---|
| backend (FastAPI + MAPE-K loop) | 89115 | 0.0 | 306.1 |
| dashboard (Streamlit) | 89116 | 1.0 | 85.0 |
| capture service | 89523 | 0.0 | 317.3 |

Pods in `target-apps` (`kubectl top`, metrics-server):

```
NAME                        CPU(cores)   MEMORY(bytes)   
grafana-5b9c6898f-wtvj6     54m          400Mi           
influxdb-55898db678-swh6r   1m           96Mi            
nodered-64b4d5776c-fzpx7    1m           133Mi
```

Pods in `ids-traffic` (`kubectl top`, metrics-server):

```
NAME                             CPU(cores)   MEMORY(bytes)   
traffic-benign-749894464-dp5tl   2m           13Mi
```

Pods in `ids-deception` (`kubectl top`, metrics-server):

```
no pods
```
