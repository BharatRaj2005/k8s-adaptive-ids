"""Backend client with a read-only SQLite fallback.

Reads go to the FastAPI backend. If it is unreachable, stored records are read
directly from the SQLite knowledge base through src.backend.queries, so the
dashboard keeps showing history when the backend or the cluster is down.
Controls (POST/DELETE) always need the backend.
"""
from __future__ import annotations

import os
from typing import Any, Callable

import requests
import streamlit as st

from src.backend import queries

API = os.environ.get("IDS_API_URL", "http://127.0.0.1:8000").rstrip("/")


@st.cache_data(ttl=3, show_spinner=False)
def _get(path: str, params: tuple = ()) -> Any:
    r = requests.get(API + path, params=dict(params), timeout=8)
    r.raise_for_status()
    return r.json()


def read(path: str, fallback: Callable[[], Any] | None = None, **params) -> tuple[Any, str]:
    """(data, mode) where mode is 'live' (backend) or 'offline' (SQLite fallback)."""
    clean = tuple(sorted((k, v) for k, v in params.items() if v is not None))
    try:
        return _get(path, clean), "live"
    except requests.RequestException:
        if fallback is None:
            return None, "offline"
        try:
            return fallback(), "offline"
        except Exception:
            return None, "offline"


@st.cache_data(ttl=3, show_spinner=False)
def backend_online() -> bool:
    try:
        return requests.get(API + "/api/health", timeout=2).ok
    except requests.RequestException:
        return False


def write(method: str, path: str, body: dict | None = None) -> tuple[bool, Any]:
    try:
        r = requests.request(method, API + path, json=body, timeout=120)
    except requests.RequestException as e:
        return False, f"backend unreachable: {e}"
    _get.clear()
    try:
        data = r.json()
    except ValueError:
        data = r.text
    if not r.ok:
        return False, data.get("detail", data) if isinstance(data, dict) else data
    return True, data


# --- typed helpers ------------------------------------------------------------------
def metrics():
    return read("/api/metrics", queries.metrics)


def detections(limit=500, **filters):
    return read("/api/detections", lambda: queries.detections(limit=limit, **filters), limit=limit, **filters)


def detection_stats():
    return read("/api/detections/stats", queries.detection_stats)


def alerts(limit=200):
    return read("/api/alerts", lambda: queries.behavior_alerts(limit), limit=limit)


def decisions(limit=300, include_simulated=True):
    return read("/api/deception/actions", lambda: queries.decisions(limit, None, include_simulated),
                limit=limit, include_simulated=include_simulated)


def decoys(limit=300):
    return read("/api/deception/decoys", lambda: queries.decoys(limit), limit=limit)


def interactions(limit=1000):
    return read("/api/deception/interactions", lambda: queries.interactions(limit), limit=limit)


def deception_status():
    return read("/api/deception/status", queries.controller_snapshot)


def policy():
    return read("/api/deception/policy", queries.policy)


def simulated_events(limit=100):
    return read("/api/deception/test-events", lambda: queries.simulated_events(limit), limit=limit)


def captures(limit=100):
    return read("/api/captures", lambda: queries.captures(limit), limit=limit)


def monitoring_overview(windows=60):
    def offline():
        out = queries.monitoring_overview(windows)
        out["capture"] = {"status": "unknown (backend offline)", "running": False}
        out["pending"] = []
        out["simulations"] = queries.simulation_runs(5)
        return out
    return read("/api/monitoring/overview", offline, windows=windows)


def monitoring_feed(after_id=0, limit=300, **filters):
    return read("/api/monitoring/feed", lambda: queries.monitoring_feed(after_id, limit, **filters),
                after_id=after_id, limit=limit, **filters)


def simulation_scenarios():
    return read("/api/simulations/scenarios")       # needs the backend: no offline catalogue of runnable Jobs


def simulation_logs(run_id: str, tail: int = 60):
    return read(f"/api/simulations/{run_id}/logs", tail=tail)


def simulation_cleanup(run_id: str):
    return read(f"/api/simulations/{run_id}/cleanup")


def capture_status():
    return read("/api/capture/status", lambda: {"service": {"status": "unknown (backend offline)", "running": False},
                                                "recent": queries.captures(20), "pending": []})


def model_performance():
    return read("/api/model/performance", queries.model_performance)


def evaluation():
    return read("/api/model/evaluation", queries.evaluation_reports)


def model_metrics(name: str):
    return read(f"/api/model/metrics/{name}", lambda: queries.model_metrics(name))


def k8s_status():
    return read("/api/kubernetes/status", lambda: {"connected": False, "error": "backend offline"})


def datasets():
    return read("/api/datasets")


def classes() -> dict[str, str]:
    from src.utils.config import class_names

    return read("/api/classes", lambda: {str(k): v for k, v in class_names().items()})[0] or {}
