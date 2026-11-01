# Performance Measurements

Generated 2026-11-01 09:35 UTC by `scripts/measure_performance.py` on this machine (12 CPUs, 7.6 GiB RAM, WSL2). All values are measured; unavailable sources are stated as such.

## Model (offline evaluation, active model)

- Model: `et_dataset_sqrt_lab_v6b` · accuracy 0.9669 · macro F1 0.3160 · weighted F1 0.9619 (details: `reports/model_evaluation.md`)
- Single-flow prediction latency (preprocessing + inference): median 52.1 ms, p95 71.3 ms (200 samples)
- Batch prediction: 24.6 µs per flow (16,150 flows in 397 ms)

## Live pipeline (classified capture windows)

- Capture window length: n=1199 · median 10.1 s · mean 8.8 · p95 10.1 · max 10.1
- Feature extraction (CICFlowMeter, PCAP → validated CSV): n=1199 · median 0.75 s · mean 0.73 · p95 1.04 · max 1.54
- Flows per window: n=1199 · median 99 flows · mean 127 · p95 310 · max 525
- Prediction per window: n=1199 · median 47.7 ms · mean 51.4 · p95 84.8 · max 183.9
- End-to-end (window closed → detections stored): n=1199 · median 0.96 s · mean 0.92 · p95 1.29 · max 2.31
- Detection delay therefore ≈ window length (5–30 s, adaptive) + the end-to-end figure above.

## Deception

- Decoy deployment time (create → first ready replica): n=22 · median 15.4 s · mean 14.7 · p95 16.0 · max 17.3
- Last MAPE-K cycle: 18 ms

## Resource usage

Host processes (psutil, CPU sampled over 1 s):

| Process | PID | CPU % | RSS MB |
|---|---|---|---|
| backend (FastAPI + MAPE-K loop) | 68553 | 2.0 | 281.4 |
| dashboard (Streamlit) | 68554 | 1.0 | 84.8 |
| capture service | 68599 | 0.0 | 1110.4 |

Pods in `target-apps` (`kubectl top`, metrics-server):

```
NAME                        CPU(cores)   MEMORY(bytes)   
grafana-5b9c6898f-wtvj6     32m          399Mi           
influxdb-55898db678-swh6r   1m           81Mi            
nodered-64b4d5776c-fzpx7    2m           94Mi
```

Pods in `ids-traffic` (`kubectl top`, metrics-server):

```
NAME                             CPU(cores)   MEMORY(bytes)   
traffic-benign-749894464-dp5tl   2m           23Mi
```

Pods in `ids-deception` (`kubectl top`, metrics-server):

```
no pods
```
