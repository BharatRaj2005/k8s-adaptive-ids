# API Reference

Generated from the FastAPI OpenAPI schema by `scripts/gen_api_docs.py` (K8s Adaptive IDS & Deception API v1.0). Interactive docs: `http://127.0.0.1:8000/docs` while the backend runs.

Base URL: `http://127.0.0.1:8000`. All bodies are JSON. Errors return `{"detail": ...}` with 400 (invalid input), 404 (unknown file/model), 409 (conflict: capture already running, decoy already active), 422 (schema validation), 503 (Kubernetes unavailable for a decoy operation) or 500 (logged internal error).

## Health & metrics

### `GET /api/health`

Database, model, Kubernetes, capture-service and deception-controller status.


### `GET /api/metrics`

Dashboard counters: flows (benign/malicious, by source), active threats (live sources, 15 min), decoys, interactions, decisions, model accuracy.


### `GET /api/classes`

Label id to class name mapping.


## Detections

### `GET /api/detections`

Stored per-flow detections, newest first (simulated events are never included).

Parameters:
  - `limit` (query, integer, default `200`, minimum 1, maximum 5000)
  - `offset` (query, integer, default `0`, minimum 0)
  - `source` (query, string, one of ['dataset', 'pcap', 'live'])
  - `predicted_class` (query, string)
  - `src_ip` (query, string)
  - `dst_ip` (query, string)
  - `malicious` (query, boolean)

### `GET /api/detections/latest`

The most recent detections.

Parameters:
  - `limit` (query, integer, default `20`, minimum 1, maximum 500)

### `GET /api/detections/stats`

Aggregates: counts per source/class, per-minute timeline, confidence buckets.


### `GET /api/alerts`

Per-source flow bursts from the behavioural detector.

Parameters:
  - `limit` (query, integer, default `200`, minimum 1, maximum 5000)

### `GET /api/datasets`

Flow CSVs available for detection runs: dataset capture files and captured windows.


### `POST /api/detection/run`

Classify a dataset capture file (offline mode) or a captured flow CSV and store the detections. Only names listed by /api/datasets are accepted.

Body:
  - `file` (string, required) — dataset capture file name (see /api/datasets) or a CSV in captures/flows
  - `max_rows` (integer, default `30000`, minimum 1.0, maximum 100000.0)

## Capture

### `POST /api/capture/start`

Start the background capture service (one tcpdump per adaptive window on the configured interface). 409 if a capture is already running.

Body:
  - `windows` (integer | null) — stop after N windows (default: until stopped)
  - `process` (boolean, default `true`)

### `POST /api/capture/stop`

Stop the capture service; the window in progress is finished and processed.


### `GET /api/capture/status`

Capture service state, recent windows and PCAPs not yet classified.


### `GET /api/captures`

Capture windows with conversion, prediction and pipeline timings.

Parameters:
  - `limit` (query, integer, default `100`, minimum 1, maximum 2000)

### `POST /api/capture/process`

Convert and classify one PCAP from captures/pcap (bare file name) or all pending PCAPs.

Body:
  - `pcap` (string | null) — file name inside captures/pcap; omitted = all pending
  - `limit` (integer, default `20`, minimum 1.0, maximum 200.0)

## Deception (MAPE-K)

### `GET /api/deception/status`

MAPE-K controller state: enabled flag, current stage, last cycle, active decoys, limits and thresholds.


### `GET /api/deception/policy`

Attack-to-decoy and flow-burst-to-decoy mappings, thresholds and limits (from config).


### `GET /api/deception/actions`

MAPE-K decision history with trigger, assessment, action, result and reason.

Parameters:
  - `limit` (query, integer, default `200`, minimum 1, maximum 5000)
  - `action` (query, string)
  - `include_simulated` (query, boolean, default `true`)

### `GET /api/deception/decoys`

Decoy lifecycle records (deploying, active, expired, removed, failed).

Parameters:
  - `limit` (query, integer, default `200`, minimum 1, maximum 5000)

### `POST /api/deception/decoys`

Manually deploy a decoy profile in ids-deception. 409 if already active, 503 if Kubernetes is unavailable.

Body:
  - `profile` (string, required)

### `GET /api/deception/interactions`

Requests received by decoys, collected from decoy logs.

Parameters:
  - `limit` (query, integer, default `200`, minimum 1, maximum 5000)
  - `decoy` (query, string)

### `GET /api/deception/interaction-summary`

Decoy interactions summarised per (source, decoy): requests, distinct paths, unknown-path share, status codes and a category (enumerating, repeated_access, exploring, single_probe).

Parameters:
  - `src_ip` (query, string)

### `POST /api/deception/enable`

Enable automatic deception. Only evidence arriving after this call is acted on.


### `POST /api/deception/disable`

Disable automatic decisions (housekeeping such as TTL expiry and log collection continues).


### `POST /api/deception/test-event`

Queue a clearly labelled SIMULATED attack event for testing the controller. Stored separately from detections and excluded from ML metrics.

Body:
  - `attack_class` (string, required)
  - `confidence` (number, default `0.95`, minimum 0.0, maximum 1.0)
  - `src_ip` (string | null)
  - `count` (integer, default `1`, minimum 1.0, maximum 100.0)
  - `note` (string, default `""`, maxLength 200)

### `GET /api/deception/test-events`

Simulated test events submitted so far.

Parameters:
  - `limit` (query, integer, default `100`, minimum 1, maximum 1000)

### `DELETE /api/deception/decoys/{name}`

Remove a managed decoy (its last interactions are collected first). 503 if Kubernetes is unavailable.

Parameters:
  - `name` (path, string)

### `POST /api/deception/cycle`

Run one MAPE-K cycle now (the background loop also runs every few seconds).


## Kubernetes & model

### `GET /api/kubernetes/status`

Node, namespace, pod, service and event status of the lab namespaces (read-only identity).


### `GET /api/model/performance`

Evaluation metrics of the active model, the model registry and lab validation results.


### `GET /api/model/metrics/{name}`

metrics.json of a registered model.

Parameters:
  - `name` (path, string)
