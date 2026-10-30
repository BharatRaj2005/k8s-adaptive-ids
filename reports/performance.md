# Performance Measurements

Generated 2026-10-30 18:37 UTC by `scripts/measure_performance.py` on this machine (12 CPUs, 7.6 GiB RAM, WSL2). All values are measured; unavailable sources are stated as such.

## Model (offline evaluation, active model)

- Model: `extratrees_dataset_lab` · accuracy 0.9655 · macro F1 0.2791 · weighted F1 0.9602 (details: `reports/model_evaluation.md`)
- Single-flow prediction latency (preprocessing + inference): median 41.5 ms, p95 76.6 ms (200 samples)
- Batch prediction: 28.8 µs per flow (16,150 flows in 466 ms)

## Live pipeline (classified capture windows)

- Capture window length: n=119 · median 10.1 s · mean 9.6 · p95 10.1 · max 10.1
- Feature extraction (CICFlowMeter, PCAP → validated CSV): n=119 · median 0.55 s · mean 0.59 · p95 0.86 · max 1.25
- Flows per window: n=119 · median 63 flows · mean 107 · p95 320 · max 525
- Prediction per window: n=119 · median 47.2 ms · mean 51.0 · p95 92.0 · max 169.1
- End-to-end (window closed → detections stored): n=119 · median 0.67 s · mean 0.72 · p95 1.05 · max 1.40
- Detection delay therefore ≈ window length (5–30 s, adaptive) + the end-to-end figure above.

## Deception

- Decoy deployment time (create → first ready replica): n=5 · median 15.3 s · mean 14.9 · p95 15.4 · max 15.4
- Last MAPE-K cycle: 37 ms

## Resource usage

Host processes (psutil, CPU sampled over 1 s):

| Process | PID | CPU % | RSS MB |
|---|---|---|---|
| backend (FastAPI + MAPE-K loop) | 35238 | 0.0 | 295.5 |
| dashboard (Streamlit) | 35239 | 1.0 | 85.0 |
| capture service | 39836 | 0.0 | 1107.6 |

Pods in `target-apps` (`kubectl top`, metrics-server):

```
NAME                        CPU(cores)   MEMORY(bytes)   
grafana-5b9c6898f-wtvj6     29m          378Mi           
influxdb-55898db678-swh6r   2m           79Mi            
nodered-64b4d5776c-fzpx7    1m           91Mi
```

Pods in `ids-traffic` (`kubectl top`, metrics-server):

```
NAME                             CPU(cores)   MEMORY(bytes)   
traffic-benign-749894464-9dlbv   3m           16Mi
```

Pods in `ids-deception` (`kubectl top`, metrics-server):

```
no pods
```
