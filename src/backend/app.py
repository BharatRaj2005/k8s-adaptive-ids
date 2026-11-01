"""FastAPI backend: detections, capture control, MAPE-K deception, cluster status.

    .venv/bin/uvicorn src.backend.app:app --host 127.0.0.1 --port 8000

Security notes: no endpoint executes shell commands; capture and conversion run
predefined argument-list commands; file names are resolved only inside the
capture directory or the dataset's own file list; overlapping captures are
refused; the deception controller can be disabled independently.
"""
from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.backend import k8s_status, queries
from src.capture import service as capture_service
from src.capture.process_pcap import pending_pcaps, process_pcap, resolve_pcap
from src.deception.controller import MapeKController
from src.deception.k8s_decoys import DecoyError
from src.preprocessing.dataset import discover_capture_files
from src.simulation.manager import SimulationError, SimulationManager
from src.utils import db
from src.utils.config import class_names, get_path, load_config
from src.utils.logging_setup import get_logger

log = get_logger("backend")
CFG = load_config()
STATE: dict[str, Any] = {}
_predictor_lock = threading.Lock()


def predictor():
    with _predictor_lock:
        if "predictor" not in STATE:
            from src.detection.predictor import FlowPredictor
            STATE["predictor"] = FlowPredictor.from_config(cfg=CFG)
        return STATE["predictor"]


def controller() -> MapeKController:
    return STATE["controller"]


def simulator() -> SimulationManager:
    return STATE["simulator"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    ctl = MapeKController(CFG)
    STATE["controller"] = ctl
    ctl.start()  # housekeeping always; decisions only while enabled
    sim = SimulationManager(CFG)
    STATE["simulator"] = sim
    # runs left active by a previous backend process: close them and remove their Jobs/Pods
    threading.Thread(target=lambda: STATE.__setitem__("simulator_recovery", sim.recover()),
                     name="simulator-recovery", daemon=True).start()
    log.info("backend started; deception enabled=%s", ctl.enabled)
    yield
    ctl.stop()


app = FastAPI(title="K8s Adaptive IDS & Deception API", version="1.0", lifespan=lifespan)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": f"internal error: {type(exc).__name__}"})


# --- schemas --------------------------------------------------------------------------

class CaptureStart(BaseModel):
    windows: int | None = Field(None, ge=1, le=10000, description="stop after N windows (default: until stopped)")
    process: bool = True


class ProcessRequest(BaseModel):
    pcap: str | None = Field(None, description="file name inside captures/pcap; omitted = all pending")
    limit: int = Field(20, ge=1, le=200)


class DetectionRun(BaseModel):
    file: str = Field(..., description="dataset capture file name (see /api/datasets) or a CSV in captures/flows")
    max_rows: int = Field(30000, ge=1, le=100000)


class TestEvent(BaseModel):
    attack_class: str
    confidence: float = Field(0.95, ge=0, le=1)
    src_ip: str | None = Field(None, max_length=64)
    count: int = Field(1, ge=1, le=100)
    note: str = Field("", max_length=200)


class DecoyRequest(BaseModel):
    profile: str


class SimulationRequest(BaseModel):
    category: Literal["recon", "benign", "attack"]
    scenario: str = Field(..., max_length=32, description="scenario key from /api/simulations/scenarios")
    target: str = Field(..., max_length=32, description="application name from the scenario catalogue ('all' for the sweep)")
    duration_s: int | None = Field(None, description="within simulator.limits.duration_s")
    rate_per_s: float | None = Field(None, description="approximate requests per second, within simulator.limits")
    max_requests: int | None = Field(None, description="within simulator.limits.max_requests")


# --- health / metrics -----------------------------------------------------------------

@app.get("/api/health")
def health():
    """Database, model, Kubernetes, capture-service and deception-controller status."""
    ctl = controller()
    db_ok = True
    try:
        with db.connect(db.db_path(CFG)) as c:
            c.execute("SELECT 1")
    except Exception:
        db_ok = False
    model_dir = get_path("models_dir", CFG) / CFG["detection"]["active_model"]
    return {"status": "ok" if db_ok else "degraded", "database": db_ok,
            "model": CFG["detection"]["active_model"], "model_available": (model_dir / "model.joblib").exists(),
            "kubernetes": ctl.manager is not None, "kubernetes_error": ctl.manager_error,
            "capture_running": capture_service.read_state(CFG)["running"], "deception_enabled": ctl.enabled,
            "controller_loop": ctl.status()["loop_running"]}


@app.get("/api/metrics")
def metrics():
    """Dashboard counters: flows (benign/malicious, by source), active threats (live sources, 15 min), decoys, interactions, decisions, model accuracy."""
    return queries.metrics(CFG)


# --- detections -----------------------------------------------------------------------

@app.get("/api/detections")
def detections(limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
               source: Literal["dataset", "pcap", "live"] | None = None, predicted_class: str | None = None,
               src_ip: str | None = None, dst_ip: str | None = None, malicious: bool | None = None):
    """Stored per-flow detections, newest first (simulated events are never included)."""
    return queries.detections(limit, offset, source, predicted_class, src_ip, dst_ip, malicious, CFG)


@app.get("/api/detections/latest")
def detections_latest(limit: int = Query(20, ge=1, le=500)):
    """The most recent detections."""
    return queries.detections(limit=limit, cfg=CFG)


@app.get("/api/detections/stats")
def detection_stats():
    """Aggregates: counts per source/class, per-minute timeline, confidence buckets."""
    return queries.detection_stats(CFG)


@app.get("/api/alerts")
def alerts(limit: int = Query(200, ge=1, le=5000)):
    """Per-source flow bursts from the behavioural detector."""
    return queries.behavior_alerts(limit, CFG)


@app.get("/api/datasets")
def datasets():
    """Flow CSVs available for detection runs: dataset capture files and captured windows."""
    files = [{"file": p.name, "kind": p.parent.name, "bytes": p.stat().st_size} for p in discover_capture_files(CFG)]
    flows = [{"file": p.name, "kind": "captured", "bytes": p.stat().st_size}
             for p in sorted(get_path("flows_dir", CFG).glob("*.csv"))[-50:]]
    return {"dataset": files, "captured": flows}


def _resolve_csv(name: str) -> tuple[Path, str]:
    if "/" in name or "\\" in name or not name.endswith(".csv"):
        raise HTTPException(400, "file must be a bare .csv file name")
    for p in discover_capture_files(CFG):
        if p.name == name:
            return p, "dataset"
    p = get_path("flows_dir", CFG) / name
    if p.is_file():
        return p, "pcap"
    raise HTTPException(404, f"{name} is not a dataset capture or captured flow file")


@app.post("/api/detection/run")
def detection_run(req: DetectionRun):
    """Classify a dataset capture file (offline mode) or a captured flow CSV and store the detections. Only names listed by /api/datasets are accepted."""
    from src.preprocessing.schema import read_flow_csv

    path, source = _resolve_csv(req.file)
    df = read_flow_csv(path)
    if len(df) > req.max_rows:
        df = df.sample(req.max_rows, random_state=0).sort_index()
    pr = predictor()
    pred = pr.predict_frame(df, capture_file=path.name, source=source)
    with db.connect(db.db_path(CFG)) as c:
        stored = db.insert_detections(c, pred)
    known = pred["true_label"].notna()
    return {"file": path.name, "source": source, "model": pr.name, "flows": stored,
            "malicious": int(pred["is_malicious"].sum()), "batch_ms": pr.last_report["batch_ms"],
            "classes": pred["predicted_class"].value_counts().to_dict(),
            "agreement_with_file_labels": float((pred.loc[known, "true_label"] == pred.loc[known, "predicted_label"]).mean())
            if known.any() else None,
            "note": "agreement is not an evaluation when the file was used for training"}


# --- capture --------------------------------------------------------------------------

@app.post("/api/capture/start")
def capture_start(req: CaptureStart):
    """Start the background capture service (one tcpdump per adaptive window on the configured interface). 409 if a capture is already running."""
    try:
        return capture_service.start(req.windows, req.process, CFG)
    except capture_service.ServiceError as e:
        raise HTTPException(409, str(e))
    except capture_service.CaptureError as e:
        raise HTTPException(400, str(e))


@app.post("/api/capture/stop")
def capture_stop():
    """Stop the capture service; the window in progress is finished and processed."""
    return capture_service.stop(CFG)


@app.get("/api/capture/status")
def capture_status():
    """Capture service state, recent windows and PCAPs not yet classified."""
    return {"service": capture_service.read_state(CFG), "recent": queries.captures(20, CFG),
            "pending": [p.name for p in pending_pcaps(CFG)]}


@app.get("/api/captures")
def captures(limit: int = Query(100, ge=1, le=2000)):
    """Capture windows with conversion, prediction and pipeline timings."""
    return queries.captures(limit, CFG)


@app.post("/api/capture/process")
def capture_process(req: ProcessRequest):
    """Convert and classify one PCAP from captures/pcap (bare file name) or all pending PCAPs."""
    if req.pcap:
        if "/" in req.pcap or "\\" in req.pcap:
            raise HTTPException(400, "pcap must be a bare file name")
        try:
            targets = [resolve_pcap(get_path("pcap_dir", CFG) / req.pcap, CFG)]
        except (ValueError, FileNotFoundError) as e:
            raise HTTPException(404, str(e))
    else:
        targets = pending_pcaps(CFG)[: req.limit]
    return {"processed": [process_pcap(p, predictor(), CFG) for p in targets]}


# --- unified live monitoring ----------------------------------------------------------

@app.get("/api/monitoring/overview")
def monitoring_overview(windows: int = Query(60, ge=1, le=500)):
    """Live Security Monitoring in one read: capture-service state, counters (captured traffic only), the latest capture windows with per-window benign/malicious/unknown/alert counts and timings, class and source distributions, and behavioural alerts of those windows."""
    out = queries.monitoring_overview(windows, CFG)
    out["capture"] = capture_service.read_state(CFG)
    out["pending"] = [p.name for p in pending_pcaps(CFG)]
    out["simulations"] = queries.simulation_runs(5, CFG)
    return out


# --- attack simulator -----------------------------------------------------------------

def _sim_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except SimulationError as e:
        raise HTTPException(e.status_code, str(e))


@app.get("/api/simulations/scenarios")
def simulation_scenarios():
    """Predefined simulator scenarios (reconnaissance scanners, benign traffic profiles), allowed target applications, parameter limits and lifecycle stages."""
    return simulator().scenarios()


@app.post("/api/simulations", status_code=201)
def simulation_start(req: SimulationRequest):
    """Start a controlled traffic-generation Job in ids-traffic. Validates the scenario and limits, checks that the target is ready, attaches to (or starts) the capture. 409 while another run is active; 422 for invalid parameters; 503 if Kubernetes is unavailable."""
    return _sim_call(simulator().start, req.category, req.scenario, req.target, req.duration_s, req.rate_per_s,
                     req.max_requests)


@app.get("/api/simulations")
def simulation_list(limit: int = Query(20, ge=1, le=200)):
    """Recent simulation runs, newest first, with stage timestamps and results."""
    return simulator().list(limit)


@app.get("/api/simulations/{run_id}")
def simulation_status(run_id: str):
    """Status of one run: lifecycle stage, generator pod and IP, requests, windows, detections, alerts and cleanup result."""
    run = simulator().get(run_id)
    if run is None:
        raise HTTPException(404, f"unknown run {run_id}")
    return run


@app.get("/api/simulations/{run_id}/predictions")
def simulation_predictions(run_id: str):
    """Actual ML predicted-class breakdown for the run's generator flows (compare with the expected class)."""
    if simulator().get(run_id) is None:
        raise HTTPException(404, f"unknown run {run_id}")
    return {"run_id": run_id, "predictions": queries.simulation_predictions(run_id, CFG)}


@app.get("/api/simulations/{run_id}/logs")
def simulation_logs(run_id: str, tail: int = Query(200, ge=1, le=5000)):
    """Generator log lines of a run (JSON lines: connections with local ports, requests); saved before the Job is deleted."""
    return _sim_call(simulator().logs, run_id, tail)


@app.post("/api/simulations/{run_id}/cancel")
def simulation_cancel(run_id: str):
    """Cancel an active run: the Job is stopped and deleted after its logs are collected; captured windows are still processed."""
    return _sim_call(simulator().cancel, run_id)


@app.get("/api/simulations/{run_id}/cleanup")
def simulation_cleanup(run_id: str):
    """Jobs and Pods of the run that still exist (listed by its labels), plus the recorded cleanup result."""
    if simulator().get(run_id) is None:
        raise HTTPException(404, f"unknown run {run_id}")
    return _sim_call(simulator().cleanup_status, run_id)


@app.post("/api/simulations/recover")
def simulation_recover():
    """Recovery cleanup (also run at startup): closes runs left active and deletes leftover simulator Jobs/Pods."""
    return simulator().recover()


@app.get("/api/monitoring/feed")
def monitoring_feed(after_id: int = Query(0, ge=0, description="only flows with a larger detection id (incremental polling)"),
                    limit: int = Query(300, ge=1, le=2000), predicted_class: str | None = Query(None, max_length=64),
                    src_ip: str | None = Query(None, max_length=64), app_name: str | None = Query(None, alias="app", max_length=32),
                    status: Literal["benign", "attack", "unknown"] | None = None,
                    mechanism: Literal["ml", "behavioural", "both", "none"] | None = None,
                    origin: Literal["simulation", "observed"] | None = None):
    """Classified flows of captured windows, newest first: status (benign / attack / unknown), whether a behavioural alert covers the flow, capture window id and the simulation run whose generator produced it (if any)."""
    return queries.monitoring_feed(after_id, limit, predicted_class, src_ip, app_name, status, mechanism, origin, CFG)


# --- deception ------------------------------------------------------------------------

@app.get("/api/deception/status")
def deception_status():
    """MAPE-K controller state: enabled flag, current stage, last cycle, active decoys, limits and thresholds."""
    return controller().status()


@app.get("/api/deception/policy")
def deception_policy():
    """Attack-to-decoy and flow-burst-to-decoy mappings, thresholds and limits (from config)."""
    return queries.policy(CFG)


@app.get("/api/deception/actions")
def deception_actions(limit: int = Query(200, ge=1, le=5000), action: str | None = None,
                      include_simulated: bool = True):
    """MAPE-K decision history with trigger, assessment, action, result and reason."""
    return queries.decisions(limit, action, include_simulated, CFG)


@app.get("/api/deception/decoys")
def deception_decoys(limit: int = Query(200, ge=1, le=5000)):
    """Decoy lifecycle records (deploying, active, expired, removed, failed)."""
    return queries.decoys(limit, CFG)


@app.get("/api/deception/interactions")
def deception_interactions(limit: int = Query(200, ge=1, le=5000), decoy: str | None = None):
    """Requests received by decoys, collected from decoy logs."""
    return queries.interactions(limit, decoy, CFG)


@app.get("/api/deception/interaction-summary")
def deception_interaction_summary(src_ip: str | None = Query(None, max_length=64)):
    """Decoy interactions summarised per (source, decoy): requests, distinct paths, unknown-path share, status codes and a category (enumerating, repeated_access, exploring, single_probe)."""
    return queries.interaction_summary(src_ip, CFG)


@app.post("/api/deception/enable")
def deception_enable():
    """Enable automatic deception. Only evidence arriving after this call is acted on."""
    controller().set_enabled(True)
    return controller().status()


@app.post("/api/deception/disable")
def deception_disable():
    """Disable automatic decisions (housekeeping such as TTL expiry and log collection continues)."""
    controller().set_enabled(False)
    return controller().status()


@app.post("/api/deception/test-event")
def deception_test_event(ev: TestEvent):
    """Queue a clearly labelled SIMULATED attack event for testing the controller. Stored separately from detections and excluded from ML metrics."""
    try:
        eid = controller().submit_simulated_event(ev.attack_class, ev.confidence, ev.src_ip, ev.count, ev.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"simulated_event_id": eid, "simulated": True,
            "note": "SIMULATED event: stored separately from ML detections and excluded from ML metrics"}


@app.get("/api/deception/test-events")
def deception_test_events(limit: int = Query(100, ge=1, le=1000)):
    """Simulated test events submitted so far."""
    return queries.simulated_events(limit, CFG)


@app.post("/api/deception/decoys")
def deception_deploy(req: DecoyRequest):
    """Manually deploy a decoy profile in ids-deception. 409 if already active, 503 if Kubernetes is unavailable."""
    try:
        res = controller().manual_deploy(req.profile)
    except DecoyError as e:
        raise HTTPException(409 if "already" in str(e) else 400, str(e))
    if res["result"] != "ok":
        raise HTTPException(503, res["error"] or "deployment failed")
    return res


@app.delete("/api/deception/decoys/{name}")
def deception_remove(name: str):
    """Remove a managed decoy (its last interactions are collected first). 503 if Kubernetes is unavailable."""
    try:
        res = controller().manual_remove(name)
    except DecoyError as e:
        raise HTTPException(400, str(e))
    if res["result"] != "ok":
        raise HTTPException(503, f"could not remove {name}: Kubernetes unavailable or API error")
    return res


@app.post("/api/deception/cycle")
def deception_cycle():
    """Run one MAPE-K cycle now (the background loop also runs every few seconds)."""
    return controller().run_cycle()


# --- kubernetes / model ---------------------------------------------------------------

@app.get("/api/kubernetes/status")
def kubernetes_status():
    """Node, namespace, pod, service and event status of the lab namespaces (read-only identity)."""
    return k8s_status.cluster_status(CFG)


@app.get("/api/model/performance")
def model_performance():
    """Evaluation metrics of the active model, the model registry and lab validation results."""
    return queries.model_performance(CFG)


@app.get("/api/model/metrics/{name}")
def model_metrics(name: str):
    """metrics.json of a registered model."""
    m = queries.model_metrics(name, CFG)
    if m is None:
        raise HTTPException(404, f"{name} is not a registered model")
    return m


@app.get("/api/model/evaluation")
def model_evaluation():
    """Summaries of reports/model_comparison.json (same-protocol candidate comparison), behavioural_detection.json (fixed vs adaptive vs ML vs hybrid on recorded lab sessions) and unknown_traffic.json (leave-one-application-out)."""
    return queries.evaluation_reports(CFG)


@app.get("/api/classes")
def classes():
    """Label id to class name mapping."""
    return class_names(CFG)
