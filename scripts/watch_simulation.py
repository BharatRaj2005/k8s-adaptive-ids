"""Follow a simulation run through the API and check the cluster afterwards (live validation helper).

    .venv/bin/python scripts/watch_simulation.py [run_id] [--cancel-at-stage traffic] [--json out.json]

Without run_id the newest run is followed. Prints every stage as it is reached, the final record,
the remaining Jobs/Pods of the run and the state of the lab namespaces.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time

import requests

API = os.environ.get("IDS_API_URL", "http://127.0.0.1:8000")
ENV = {**os.environ, "KUBECONFIG": os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))}
ACTIVE = ("requested", "running", "processing")


def kubectl(*args: str) -> str:
    return subprocess.run(["kubectl", *args], env=ENV, capture_output=True, text=True).stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id", nargs="?")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--json")
    args = ap.parse_args()
    run_id = args.run_id or requests.get(f"{API}/api/simulations", params={"limit": 1}).json()[0]["run_id"]
    seen, t0, last = set(), time.time(), None
    while time.time() - t0 < args.timeout:
        try:
            run = requests.get(f"{API}/api/simulations/{run_id}", timeout=5).json()
        except requests.RequestException as e:
            print(f"{time.strftime('%H:%M:%S')} backend unreachable: {type(e).__name__}", flush=True)
            time.sleep(2)
            continue
        for stage, ts in (run.get("stages") or {}).items():
            if stage not in seen:
                seen.add(stage)
                print(f"{time.strftime('%H:%M:%S')} stage {stage:18s} at {ts[11:19]}  status={run['status']}", flush=True)
        last = run
        if run["status"] not in ACTIVE:
            break
        time.sleep(1)
    keys = ("run_id", "status", "profile", "target", "pod_name", "pod_ip", "capture_owned", "requests", "connections",
            "packets", "flows", "detections", "attacks", "unknown", "alerts", "capture_ids", "cleanup", "error", "log_file")
    print(json.dumps({k: last.get(k) for k in keys}, indent=1))
    print("cleanup endpoint:", json.dumps(requests.get(f"{API}/api/simulations/{run_id}/cleanup").json()))
    print("jobs/pods with run label:", kubectl("-n", "ids-traffic", "get", "jobs,pods", "-l", f"ids.lab/sim-run={run_id}",
                                               "--no-headers") or "none")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(last, fh, indent=1, default=str)


if __name__ == "__main__":
    main()
