"""Resource profile of one trained model, measured in a fresh process.

    python -m src.detection.profile_model models/<name> --csv <flows.csv> [--json]

Reports the file size, RSS after the Python imports (baseline), RSS after loading
the model, peak RSS while predicting, and latency for single flows and for the
batch. Running in its own process keeps other models and the training data out
of the measurement.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np


def _status_mb(field: str) -> float:
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith(field + ":"):
                return int(line.split()[1]) / 1024
    return float("nan")


def rss_mb() -> float:
    return _status_mb("VmRSS")


def peak_mb() -> float:
    # VmHWM belongs to this process image. getrusage(ru_maxrss) is not used: it survives
    # exec, so a child started by a large parent would report the parent's peak.
    return _status_mb("VmHWM")


def profile(model_dir: Path, csv: Path, single: int = 200) -> dict:
    import pandas as pd  # noqa: F401  (counted in the import baseline)
    import sklearn  # noqa: F401

    from src.detection.predictor import FlowPredictor
    from src.preprocessing.schema import read_flow_csv

    flows = read_flow_csv(csv)
    base = rss_mb()
    t0 = time.perf_counter()
    pred = FlowPredictor(model_dir)
    load_s = time.perf_counter() - t0
    loaded = rss_mb()
    cpu0 = time.process_time()
    t0 = time.perf_counter()
    pred.predict_frame(flows, source="unknown")
    batch_s = time.perf_counter() - t0
    batch_cpu = time.process_time() - cpu0
    rng = np.random.default_rng(0)
    idx = rng.choice(len(flows), size=min(single, len(flows)), replace=False)
    lat = []
    for i in idx:
        row = flows.iloc[[int(i)]]
        t = time.perf_counter()
        pred.predict_frame(row, source="unknown")
        lat.append((time.perf_counter() - t) * 1000)
    lat = np.asarray(lat)
    return {
        "model": model_dir.name,
        "model_bytes": sum(f.stat().st_size for f in model_dir.glob("*.joblib")),
        "rss_imports_mb": round(base, 1),
        "rss_loaded_mb": round(loaded, 1),
        "model_rss_mb": round(loaded - base, 1),
        "peak_rss_mb": round(peak_mb(), 1),
        "load_seconds": round(load_s, 3),
        "batch_rows": int(len(flows)),
        "batch_ms": round(batch_s * 1000, 2),
        "batch_cpu_ms": round(batch_cpu * 1000, 2),
        "batch_per_flow_us": round(batch_s / max(len(flows), 1) * 1e6, 2),
        "single_flow_median_ms": round(float(np.median(lat)), 3),
        "single_flow_p95_ms": round(float(np.percentile(lat, 95)), 3),
        "pid": os.getpid(),
    }


def profile_in_subprocess(model_dir: Path, csv: Path, python: str | None = None) -> dict:
    import subprocess

    from src.utils.config import PROJECT_ROOT

    out = subprocess.run([python or sys.executable, "-m", "src.detection.profile_model", str(model_dir),
                          "--csv", str(csv), "--json"], cwd=PROJECT_ROOT, capture_output=True, text=True,
                         timeout=900, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model_dir", type=Path)
    ap.add_argument("--csv", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    res = profile(args.model_dir, args.csv)
    print(json.dumps(res) if args.json else json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
