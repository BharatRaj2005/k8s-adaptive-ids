"""Capture fresh BENIGN traffic for an independent fast-benign validation set.

Covers: fast API clients (~8 req/s) on all three apps, bursty browsing, normal
browsing and polling. Every run is benign (no attacker args), so the whole
generated traffic is benign ground truth. Each run becomes its own lab set under
data/lab/, kept separate from training (except the *_train sets, see RUNS). A sidecar mapping (set -> run_id, pod_ip,
scenario) is written so the scorer can isolate the generator pod's flows.

No model change. One run at a time.
"""
import json
import sys
import time
from datetime import timedelta

from src.preprocessing.lab_data import snapshot
from src.simulation.manager import SimulationManager, _now, _parse
from src.utils.config import load_config

CFG = load_config()
TERMINAL = {"completed", "cancelled", "timeout", "failed"}
META_PATH = "data/lab/fastbenign_meta.json"

# (category, scenario, target, lab-set name, note)
RUNS = [
    ("benign", "api_client", "nodered", "fbenign_api_nodered", "fast API ~8/s -> Node-RED"),
    ("benign", "api_client", "grafana", "fbenign_api_grafana", "fast API ~8/s -> Grafana"),
    ("benign", "api_client", "influxdb", "fbenign_api_influxdb", "fast API ~8/s -> InfluxDB"),
    ("benign", "burst", "nodered", "fbenign_burst_nodered", "bursty dashboard refresh -> Node-RED"),
    ("benign", "browse", "grafana", "fbenign_browse_grafana", "normal browsing -> Grafana"),
    ("benign", "poller", "all", "fbenign_poller_all", "normal polling -> all apps"),
    # TRAINING sets (separate runs): fast/bursty benign counterexamples for the Grafana/InfluxDB recon
    # training sets, so the model does not learn "fast traffic to these apps = recon". Added via
    # --lab-train; the sets above stay held out.
    ("benign", "api_client", "nodered", "fbenign_api_nodered_train", "TRAIN: fast API ~8/s -> Node-RED"),
    ("benign", "api_client", "grafana", "fbenign_api_grafana_train", "TRAIN: fast API ~8/s -> Grafana"),
    ("benign", "api_client", "influxdb", "fbenign_api_influxdb_train", "TRAIN: fast API ~8/s -> InfluxDB"),
    ("benign", "burst", "grafana", "fbenign_burst_grafana_train", "TRAIN: bursty dashboard refresh -> Grafana"),
    ("benign", "browse", "grafana", "fbenign_browse_grafana_train", "TRAIN: normal browsing -> Grafana"),
    ("benign", "browse", "nodered", "fbenign_browse_nodered_train", "TRAIN: normal browsing -> Node-RED"),
    # held-out benign of behaviour types absent from all training sets (generalisation check)
    ("benign", "keepalive", "grafana", "fbenign_keepalive_grafana", "keep-alive API client -> Grafana (eval)"),
    ("benign", "poller", "influxdb", "fbenign_poller_influxdb", "health/metrics poller -> InfluxDB (eval)"),
    # poller counterexample for the slow-recon training set, and a held-out poller on the same app
    ("benign", "poller", "nodered", "fbenign_poller_nodered_train", "TRAIN: health/metrics poller -> Node-RED"),
    ("benign", "poller", "nodered", "fbenign_poller_nodered", "health/metrics poller -> Node-RED (eval)"),
    ("benign", "burst", "nodered", "fbenign_burst_nodered_train", "TRAIN: bursty dashboard refresh -> Node-RED"),
]

mgr = SimulationManager()


def run_one(category, scenario, target, name, note):
    print("\n### %s: %s/%s -> %s" % (name, category, scenario, target), flush=True)
    rec = mgr.start(category, scenario, target)
    rid = rec["run_id"]
    print("  run %s started" % rid, flush=True)
    deadline = time.monotonic() + 400
    while time.monotonic() < deadline:
        time.sleep(3)
        r = mgr.get(rid)
        if r["status"] in TERMINAL and not r.get("thread_alive"):
            break
    r = mgr.get(rid)
    pod_ip = r.get("pod_ip")
    st = _parse(r.get("created_at")) - timedelta(seconds=3)
    en = _parse(r.get("finished_at") or _now()) + timedelta(seconds=3)
    print("  status=%s pod_ip=%s error=%s" % (r["status"], pod_ip, r.get("error")), flush=True)
    if not pod_ip:
        print("  NO POD IP - skipping snapshot", flush=True)
        return None
    snapshot(name, st.isoformat(), en.isoformat(), note=note)  # benign: no attacker args -> all benign
    return {"run_id": rid, "pod_ip": pod_ip, "scenario": scenario, "target": target,
            "from": st.isoformat(), "to": en.isoformat(), "note": note}


if __name__ == "__main__":
    only = set(sys.argv[1:])
    try:  # merge: a partial run must not drop the metadata of sets captured earlier
        with open(META_PATH) as fh:
            meta = json.load(fh)
    except FileNotFoundError:
        meta = {}
    for args in RUNS:
        if only and args[3] not in only:
            continue
        try:
            m = run_one(*args)
            if m:
                meta[args[3]] = m
        except Exception as e:
            print("  FAILED %s: %s: %s" % (args[3], type(e).__name__, e), flush=True)
        time.sleep(8)
    try:
        with open(META_PATH, "w") as fh:
            json.dump(meta, fh, indent=2)
        print("\nwrote %s (%d sets)" % (META_PATH, len(meta)), flush=True)
    except Exception as e:
        print("meta write failed: %s" % e, flush=True)
    print("DONE", flush=True)
