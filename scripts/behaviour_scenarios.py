"""Record a labelled behavioural-detection session in the lab.

    .venv/bin/python scripts/behaviour_scenarios.py --name session2 [--benign-minutes 5] [--gap 60]

Runs the existing bounded recon Job (kubernetes/traffic-generator/recon-job.yaml, HTTP
requests to Node-RED inside the lab only) at several request rates, one after the
other, while the capture service records windows. The benign generator keeps running
throughout. For every Job the pod IPs and the first/last request times (from the
generator's own JSON log lines) are written to data/lab/behavior_sessions/<name>.json,
which src.detection.behavior_eval uses as ground truth.

    .venv/bin/python scripts/behaviour_scenarios.py --name session3 --benign-shift 6

records a session without attackers in which the benign generator's request rate
is raised about 3x for the given minutes (kubectl set env restarts its pod, so it
also reappears under a new IP) and then restored; every alert in it is a false
positive.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "KUBECONFIG": os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))}
NS = "ids-traffic"

# name, delay between requests (s), requests per pod, parallel pods
SCENARIOS = [
    ("high_rate", 0.1, 300, 1),
    ("medium_rate", 1.0, 120, 1),
    ("low_rate", 3.0, 50, 1),
    ("very_low_rate", 6.0, 30, 1),
    ("distributed", 2.0, 60, 4),
]


def kubectl(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(["kubectl", *args], env=ENV, input=stdin, capture_output=True, text=True,
                          check=True).stdout.strip()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# second scanner (RECON_TARGET=grafana): different paths and target application
ALT_SCENARIOS = [
    ("alt_scanner_medium", 1.0, 120, 1),
    ("alt_scanner_low", 3.0, 50, 1),
]


def job_manifest(name: str, delay: float, requests: int, parallel: int, target: str = "nodered") -> str:
    job = yaml.safe_load((ROOT / "kubernetes/traffic-generator/recon-job.yaml").read_text())
    job = copy.deepcopy(job)
    job["metadata"]["generateName"] = f"traffic-recon-{name.replace('_', '-')}-"
    job["spec"]["parallelism"] = parallel
    job["spec"]["completions"] = parallel
    env = job["spec"]["template"]["spec"]["containers"][0]["env"]
    for e in env:
        if e["name"] == "RECON_REQUESTS":
            e["value"] = str(requests)
        if e["name"] == "RECON_DELAY":
            e["value"] = str(delay)
    env.append({"name": "RECON_TARGET", "value": target})
    return yaml.safe_dump(job)


def run_scenario(name: str, delay: float, requests: int, parallel: int, target: str = "nodered") -> list[dict]:
    job = kubectl("create", "-f", "-", "-o", "name", stdin=job_manifest(name, delay, requests, parallel, target))
    print(f"{now()} {name}: {job} ({parallel} pod(s), {requests} requests, {delay}s spacing)", flush=True)
    kubectl("-n", NS, "wait", "--for=condition=complete", job, "--timeout=400s")
    jname = job.split("/", 1)[1]
    pods = json.loads(kubectl("-n", NS, "get", "pods", "-l", f"job-name={jname}", "-o", "json"))["items"]
    out = []
    for i, p in enumerate(pods):
        lines = [json.loads(x) for x in kubectl("-n", NS, "logs", p["metadata"]["name"]).splitlines() if x.startswith("{")]
        reqs = [x for x in lines if "url" in x]
        out.append({"name": name if parallel == 1 else f"{name}_{i + 1}", "group": name,
                    "ip": p["status"]["podIP"], "kind": "recon", "job": jname, "target": target,
                    "rate_per_s": round(1 / delay, 3), "parallel": parallel,
                    "requests": len(reqs), "start": reqs[0]["ts"] if reqs else None,
                    "end": reqs[-1]["ts"] if reqs else None})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True)
    ap.add_argument("--benign-minutes", type=float, default=5)
    ap.add_argument("--gap", type=float, default=60, help="seconds of benign-only traffic between scenarios")
    ap.add_argument("--alt-scanner", action="store_true", help="run the second scanner (Grafana) scenarios")
    ap.add_argument("--benign-shift", type=float, metavar="MIN",
                    help="no attackers: raise the benign request rate for MIN minutes instead")
    args = ap.parse_args()
    out_path = ROOT / "data/lab/behavior_sessions" / f"{args.name}.json"
    if out_path.exists():
        sys.exit(f"{out_path} exists")
    state = json.loads((ROOT / "captures/capture_state.json").read_text())
    if state.get("status") != "running":
        sys.exit("start the capture service first (python -m src.capture.service start)")
    session = {"name": args.name, "from": now(), "benign_minutes": args.benign_minutes, "scenarios": []}
    print(f"{now()} benign-only period {args.benign_minutes} min", flush=True)
    time.sleep(args.benign_minutes * 60)
    if args.benign_shift:
        dep = "deployment/traffic-benign"
        print(f"{now()} benign rate x3 for {args.benign_shift} min", flush=True)
        kubectl("-n", NS, "set", "env", dep, "MIN_DELAY=0.3", "MAX_DELAY=1.3")
        session["benign_shift"] = {"start": now(), "min_delay": 0.3, "max_delay": 1.3}
        time.sleep(args.benign_shift * 60)
        kubectl("-n", NS, "set", "env", dep, "MIN_DELAY=1.0", "MAX_DELAY=4.0")   # values of benign-deployment.yaml
        session["benign_shift"]["end"] = now()
        print(f"{now()} benign rate restored", flush=True)
        time.sleep(args.gap)
    plan = [] if args.benign_shift else ([(*a, "grafana") for a in ALT_SCENARIOS] if args.alt_scanner else SCENARIOS)
    for sc in plan:
        session["scenarios"] += run_scenario(*sc)
        time.sleep(args.gap)
    session["to"] = now()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(session, indent=2))
    print("wrote", out_path)


if __name__ == "__main__":
    main()
