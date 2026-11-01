"""Capture recon lab sets: eval sets (unseen scanner, slow recon, recon on other apps) and training sets.

All are class 2 (reconnaissance). The *_train sets give the model recon signal on Grafana/InfluxDB
(added via --lab-train); every other set stays held out and is only used to validate that the
active model + MAPE-K policy still catch scanners (incl. unseen ones). No model change here.
Usage: capture_recon_labsets.py [name ...]   (no names = all runs)
"""
import sys
import time
from datetime import timedelta

from src.preprocessing.lab_data import snapshot
from src.simulation.manager import SimulationManager, _now, _parse

TERMINAL = {"completed", "cancelled", "timeout", "failed"}
PORTS = {"nodered": 1880, "grafana": 3000, "influxdb": 8086}

# (category, scenario, target, name, note) - scenario keys from config/settings.yaml simulator
RUNS = [
    ("recon", "threaded", "nodered", "recon_threaded_nodered", "unseen scanner (threaded_parallel) -> Node-RED"),
    ("recon", "slow", "nodered", "recon_slow_nodered", "slow HEAD crawl -> Node-RED"),
    ("recon", "sequential", "grafana", "recon_seq_grafana", "sequential scan -> Grafana (unseen app)"),
    # training sets (separate runs from the eval sets above/below)
    ("recon", "sequential", "grafana", "recon_grafana_train", "TRAIN: sequential scan -> Grafana"),
    ("recon", "sequential", "influxdb", "recon_influx_train", "TRAIN: sequential scan -> InfluxDB"),
    # held-out eval: same app as training, and an untrained technique on Grafana
    ("recon", "sequential", "influxdb", "recon_seq_influx", "sequential scan -> InfluxDB (eval)"),
    ("recon", "shuffled", "grafana", "recon_shuffled_grafana", "shuffled jitter scan -> Grafana (eval)"),
    # slow recon: a longer training run on Node-RED (paired with benign poller *_train sets in
    # capture_fastbenign_labsets.py) and a held-out slow run on another app
    ("recon", "slow", "nodered", "recon_slow_nodered_train", "TRAIN: slow HEAD crawl -> Node-RED",
     {"duration_s": 300, "max_requests": 90}),
    ("recon", "slow", "influxdb", "recon_slow_influx", "slow HEAD crawl -> InfluxDB (eval)"),
]

mgr = SimulationManager()


def run_one(category, scenario, target, name, note, params=None):
    print("\n### %s: %s/%s -> %s" % (name, category, scenario, target), flush=True)
    rec = mgr.start(category, scenario, target, **(params or {}))
    rid = rec["run_id"]
    print("  run %s started" % rid, flush=True)
    deadline = time.monotonic() + 500
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
        return
    man = snapshot(name, st.isoformat(), en.isoformat(), attacker_ips=[pod_ip],
                   target_port=PORTS[target], attack_label=2, note=note)
    print("  snapshot %s: %d files" % (name, len(man.get("files", []))), flush=True)


if __name__ == "__main__":
    only = set(sys.argv[1:])
    for args in RUNS:
        if only and args[3] not in only:
            continue
        try:
            run_one(*args)
        except Exception as e:
            print("  FAILED %s: %s: %s" % (args[3], type(e).__name__, e), flush=True)
        time.sleep(8)
    print("\nDONE", flush=True)
