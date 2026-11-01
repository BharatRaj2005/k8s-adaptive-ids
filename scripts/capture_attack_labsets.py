"""Capture labelled lab sets for the attack-characteristic scenarios.

For each run: start a simulator Job (own capture), wait for it to finish and for its
windows to be classified, then snapshot that time window into data/lab with the
scenario class label (attacker pod IP + target port -> attack label; the rest benign).
No change to the active model. One run at a time.
"""
import sys
import time
from datetime import timedelta

from src.datagen.plan import load_datagen_config
from src.preprocessing.lab_data import snapshot
from src.simulation.manager import SimulationManager, _now, _parse
from src.utils.config import load_config

CFG = load_config()
PORTS = {a: c["port"] for a, c in load_datagen_config()["apps"].items()}
TERMINAL = {"completed", "cancelled", "timeout", "failed"}

# (scenario, app, class_label, lab-set name, duration_s, max_requests[, rate_per_s]) - rate defaults to the
# scenario's (5/s). Request paths are the generator's fixed, safety-reviewed sets; diversity comes from rate,
# duration and each run's random seed (ordering, jitter).
RUNS = [
    ("nodered_rce", "nodered", 3, "attack_nodered_rce_train", 60, 150),
    ("nodered_rce", "nodered", 3, "attack_nodered_rce_eval", 45, 100),
    ("grafana_traversal", "grafana", 5, "attack_grafana_traversal_train", 60, 200),
    ("grafana_traversal", "grafana", 5, "attack_grafana_traversal_eval", 45, 120),
    ("influx_authbypass", "influxdb", 6, "attack_influx_authbypass_train", 60, 150),
    ("influx_authbypass", "influxdb", 6, "attack_influx_authbypass_eval", 45, 100),
    # more volume at other rates (training) and a held-out rate absent from training (eval, 1/s)
    ("nodered_rce", "nodered", 3, "attack_nodered_rce_train_r2", 120, 240, 2),
    ("nodered_rce", "nodered", 3, "attack_nodered_rce_train_r9", 40, 360, 9),
    ("nodered_rce", "nodered", 3, "attack_nodered_rce_eval_r1", 120, 120, 1),
    ("grafana_traversal", "grafana", 5, "attack_grafana_traversal_train_r2", 120, 240, 2),
    ("grafana_traversal", "grafana", 5, "attack_grafana_traversal_train_r9", 40, 360, 9),
    ("grafana_traversal", "grafana", 5, "attack_grafana_traversal_eval_r1", 120, 120, 1),
    ("influx_authbypass", "influxdb", 6, "attack_influx_authbypass_train_r2", 120, 240, 2),
    ("influx_authbypass", "influxdb", 6, "attack_influx_authbypass_train_r9", 40, 360, 9),
    ("influx_authbypass", "influxdb", 6, "attack_influx_authbypass_eval_r1", 120, 120, 1),
    # class 1 (CVE-2020-13379 avatar SSRF shape): does lab training make it separable?
    ("grafana_ssrf", "grafana", 1, "attack_grafana_ssrf_train", 60, 120),
    ("grafana_ssrf", "grafana", 1, "attack_grafana_ssrf_train_r2", 120, 240, 2),
    ("grafana_ssrf", "grafana", 1, "attack_grafana_ssrf_eval", 45, 100),
]

mgr = SimulationManager()


def run_one(scenario, app, label, name, duration, maxreq, rate=None):
    print("\n### %s: attack/%s -> %s (label %d)" % (name, scenario, app, label), flush=True)
    rec = mgr.start("attack", scenario, app, duration_s=duration, max_requests=maxreq, rate_per_s=rate)
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
    man = snapshot(name, st.isoformat(), en.isoformat(), attacker_ips=[pod_ip],
                   target_port=PORTS[app], attack_label=label, note="simulated %s" % scenario)
    counts = man.get("label_counts") or man.get("counts") or man
    print("  snapshot %s -> %s" % (name, counts), flush=True)
    return man


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
