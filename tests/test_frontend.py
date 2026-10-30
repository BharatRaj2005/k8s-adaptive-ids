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
PAGES = ["overview", "monitoring", "classification", "deception", "capture", "performance", "kubernetes"]
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
