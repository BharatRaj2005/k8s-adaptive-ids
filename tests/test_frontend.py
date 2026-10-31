"""Render every dashboard page headlessly, with and without the backend.

With the backend unreachable, pages must fall back to the stored SQLite records
and render without exceptions.
"""
import os
import sys

import pytest
import requests
from streamlit.testing.v1 import AppTest

from src.utils.config import PROJECT_ROOT

FRONTEND = PROJECT_ROOT / "frontend"
PAGES = ["overview", "live_monitoring", "classification", "deception", "performance", "kubernetes"]
LIVE_API = os.environ.get("IDS_API_URL", "http://127.0.0.1:8000")


def _backend_up() -> bool:
    try:
        return requests.get(LIVE_API + "/api/health", timeout=2).ok
    except requests.RequestException:
        return False


@pytest.fixture(autouse=True)
def frontend_path(monkeypatch):
    monkeypatch.syspath_prepend(str(FRONTEND))
    for mod in [m for m in sys.modules if m == "components" or m.startswith("components.")]:
        del sys.modules[mod]  # re-read IDS_API_URL


def _run(page: str) -> AppTest:
    at = AppTest.from_file(str(FRONTEND / "views" / f"{page}.py"), default_timeout=60)
    at.run()
    return at


@pytest.mark.parametrize("page", PAGES)
def test_page_renders_offline(page, monkeypatch):
    monkeypatch.setenv("IDS_API_URL", "http://127.0.0.1:9")  # nothing listens there
    at = _run(page)
    assert not at.exception, [e.value for e in at.exception]


@pytest.mark.skipif(not _backend_up(), reason="backend not running")
@pytest.mark.parametrize("page", PAGES)
def test_page_renders_live(page, monkeypatch):
    monkeypatch.setenv("IDS_API_URL", LIVE_API)
    at = _run(page)
    assert not at.exception, [e.value for e in at.exception]
    assert at.title and at.title[0].value


def test_app_entrypoint_renders(monkeypatch):
    monkeypatch.setenv("IDS_API_URL", "http://127.0.0.1:9")
    at = AppTest.from_file(str(FRONTEND / "app.py"), default_timeout=60)
    at.run()
    assert not at.exception, [e.value for e in at.exception]


def _panel_app(run_json: str):
    import json
    import sys
    from pathlib import Path

    import streamlit as st

    sys.path.insert(0, str(Path.cwd() / "frontend"))
    from components import simulator, ui

    ui.setup_page()
    simulator.panel([json.loads(run_json)], online=False)
    st.markdown("rendered")


@pytest.mark.parametrize("status, stages", [
    ("running", ["requested", "job_created", "pod_running"]),
    ("completed", ["requested", "job_created", "pod_running", "traffic_generated", "pcap_captured", "conversion",
                   "classification", "behavioural", "results_stored", "cleaned_up"]),
    ("failed", ["requested", "job_created"]),
    ("cancelled", ["requested", "job_created", "pod_running", "traffic_generated", "cleaned_up"]),
])
def test_simulation_panel_renders_every_status(status, stages, monkeypatch):
    import json

    monkeypatch.setenv("IDS_API_URL", "http://127.0.0.1:9")
    monkeypatch.chdir(PROJECT_ROOT)
    run = {"run_id": "sim-20261031-120000-abcd", "status": status, "category": "recon", "profile": "seq_wordlist",
           "target": "nodered", "params": {"label": "Sequential scanner", "rate_per_s": 5, "duration_s": 60,
                                           "max_requests": 200},
           "stages": {s: "2026-10-31T12:00:00+00:00" for s in stages}, "stage": stages[-1],
           "pod_name": "sim-x-abcde", "pod_ip": "10.42.0.77", "requests": 200, "connections": 200, "packets": 9000,
           "flows": 900, "detections": 400, "attacks": 180, "unknown": 0, "alerts": 3, "capture_ids": [1, 2],
           "cleanup": {"ok": True} if "cleaned_up" in stages else None, "error": "x" if status == "failed" else None,
           "created_at": "2026-10-31T12:00:00+00:00", "traffic_start": None, "traffic_end": None}
    at = AppTest.from_function(_panel_app, args=(json.dumps(run),), default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("rendered" in m.value for m in at.markdown)
