"""Collect measured performance figures into reports/performance.md.

    .venv/bin/python scripts/measure_performance.py

Sources: model metrics (offline evaluation), the captures table (feature
extraction and end-to-end pipeline times of real capture windows), the decoys
table (deployment times), psutil for the backend / dashboard / capture
processes, and `kubectl top` (metrics-server) for lab pods. Missing sources
are reported as unavailable, never estimated.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import psutil  # noqa: E402

from src.utils import db  # noqa: E402
from src.utils.config import get_path, load_config  # noqa: E402

ENV = {**os.environ, "KUBECONFIG": os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))}


def stats(s: pd.Series, unit: str, digits: int = 2) -> str:
    s = pd.to_numeric(s, errors="coerce").dropna()
    if s.empty:
        return "no data"
    return (f"n={len(s)} · median {s.median():.{digits}f} {unit} · mean {s.mean():.{digits}f} · "
            f"p95 {s.quantile(0.95):.{digits}f} · max {s.max():.{digits}f}")


def processes() -> list[dict]:
    rows = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        cmd = " ".join(p.info["cmdline"] or [])
        for key, label in (("uvicorn src.backend.app", "backend (FastAPI + MAPE-K loop)"),
                           ("streamlit run frontend/app.py", "dashboard (Streamlit)"),
                           ("src.capture.service run", "capture service")):
            if key in cmd:
                cpu = p.cpu_percent(interval=1.0)
                rows.append({"process": label, "pid": p.info["pid"], "cpu_percent_1s": cpu,
                             "rss_mb": round(p.memory_info().rss / 2**20, 1)})
    return rows


def kubectl_top(ns: str) -> str:
    try:
        return subprocess.run(["kubectl", "top", "pods", "-n", ns], env=ENV, capture_output=True, text=True,
                              timeout=20).stdout.strip() or "no pods"
    except Exception as e:
        return f"unavailable: {e}"


def main():
    cfg = load_config()
    with db.connect(db.db_path(cfg)) as c:
        caps = db.query_df(c, "SELECT * FROM captures WHERE status = 'classified'")
        dec = db.query_df(c, "SELECT * FROM decoys WHERE deploy_seconds IS NOT NULL")
        cyc = db.kv_get(c, "last_cycle")
    active = cfg["detection"]["active_model"]
    m = json.loads((get_path("models_dir", cfg) / active / "metrics.json").read_text())
    lat = m["latency"]
    caps["flows_per_s_converted"] = caps["flows"] / caps["conversion_s"]
    L = [
        "# Performance Measurements", "",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by `scripts/measure_performance.py` on this "
        f"machine ({psutil.cpu_count()} CPUs, {psutil.virtual_memory().total / 2**30:.1f} GiB RAM, WSL2). "
        "All values are measured; unavailable sources are stated as such.", "",
        "## Model (offline evaluation, active model)", "",
        f"- Model: `{active}` · accuracy {m['test']['accuracy']:.4f} · macro F1 {m['test']['f1_macro']:.4f} · "
        f"weighted F1 {m['test']['f1_weighted']:.4f} (details: `reports/model_evaluation.md`)",
        f"- Single-flow prediction latency (preprocessing + inference): median {lat['single_flow_median_ms']:.1f} ms, "
        f"p95 {lat['single_flow_p95_ms']:.1f} ms ({lat['single_flow_samples']} samples)",
        f"- Batch prediction: {lat['batch_per_flow_us']:.1f} µs per flow ({lat['batch_rows']:,} flows in "
        f"{lat['batch_total_ms']:.0f} ms)", "",
        "## Live pipeline (classified capture windows)", "",
        f"- Capture window length: {stats(caps['duration_s'], 's', 1)}",
        f"- Feature extraction (CICFlowMeter, PCAP → validated CSV): {stats(caps['conversion_s'], 's')}",
        f"- Flows per window: {stats(caps['flows'], 'flows', 0)}",
        f"- Prediction per window: {stats(caps['prediction_ms'], 'ms', 1)}",
        f"- End-to-end (window closed → detections stored): {stats(caps['pipeline_s'], 's')}",
        "- Detection delay therefore ≈ window length (5–30 s, adaptive) + the end-to-end figure above.", "",
        "## Deception", "",
        f"- Decoy deployment time (create → first ready replica): {stats(dec['deploy_seconds'], 's', 1)}",
        f"- Last MAPE-K cycle: {json.loads(cyc)['duration_ms']:.0f} ms" if cyc else "- MAPE-K cycle: no data", "",
        "## Resource usage", "",
        "Host processes (psutil, CPU sampled over 1 s):", "",
    ]
    procs = processes()
    if procs:
        L += ["| Process | PID | CPU % | RSS MB |", "|---|---|---|---|"]
        L += [f"| {p['process']} | {p['pid']} | {p['cpu_percent_1s']:.1f} | {p['rss_mb']} |" for p in procs]
    else:
        L.append("No backend/dashboard/capture process running at measurement time.")
    for ns in ("target-apps", "ids-traffic", "ids-deception"):
        L += ["", f"Pods in `{ns}` (`kubectl top`, metrics-server):", "", "```", kubectl_top(ns), "```"]
    out = get_path("reports_dir", cfg) / "performance.md"
    out.write_text("\n".join(L) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()
