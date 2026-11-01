"""Dry-run the MAPE-K controller on the live evidence of one simulator run.

Feeds the run's real detections and behavioural alerts (as stored by the live pipeline, incl. the
slow_scan / adaptive_rate detectors) to the real controller analyze() + plan(), with the clock set
to the end of the run. execute() is never called and the database is opened read-only, so no decoy
is deployed and nothing is written.
Usage: dryrun_mapek_run.py <sim_run_id>
"""
import sqlite3
import sys
from collections import Counter
from datetime import timedelta

from src.deception import controller as ctl
from src.utils import db
from src.utils.config import load_config

CFG = load_config()


def main(run_id):
    c = sqlite3.connect(f"file:{db.db_path(CFG)}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    try:
        run = dict(c.execute("SELECT * FROM simulation_runs WHERE run_id = ?", (run_id,)).fetchone())
        pod = run["pod_ip"]
        sources = CFG["deception"]["act_on_sources"]
        q = ",".join("?" * len(sources))
        dets = [dict(r) for r in c.execute(
            f"SELECT * FROM detections WHERE sim_run_id = ? AND src_ip = ? AND is_malicious = 1 AND simulated = 0 "
            f"AND source IN ({q}) ORDER BY id", (run_id, pod, *sources))]
        alerts = [dict(r) for r in c.execute(
            "SELECT * FROM behavior_alerts WHERE sim_run_id = ? AND src_ip = ? ORDER BY id", (run_id, pod))]
        total = c.execute("SELECT COUNT(*) FROM detections WHERE sim_run_id = ? AND src_ip = ?", (run_id, pod)).fetchone()[0]
        print("run %s %s/%s -> %s  status=%s pod=%s" % (run_id, run["category"], run["profile"], run["target"],
                                                       run["status"], pod))
        print("pod flows classified: %d  malicious: %d  classes: %s" % (
            total, len(dets), dict(Counter(d["predicted_class"] for d in dets))))
        print("behaviour alerts: %d  types: %s" % (len(alerts), dict(Counter(a["alert_type"] for a in alerts))))
        end = ctl.parse(run["finished_at"] or run["traffic_end"]) + timedelta(seconds=1)
        ctl.now_utc = lambda: end  # analyze()/plan() look back repeat_window_seconds from "now"
        mc = ctl.MapeKController(CFG)
        actions = mc.plan(c, mc.analyze(c, {"detections": dets, "alerts": alerts, "simulated": []}))
        print("\nplanned actions (dry run, not executed):")
        for a in actions:
            print("  [%s] %s %s -> %s: %s" % (a["trigger"], a["assessment"], a["attack_class"], a["action"], a["reason"]))
        if not actions:
            print("  none")
        deploy = any(a["action"] == "deploy" for a in actions)
        print("\nWOULD DEPLOY A DECOY: %s" % deploy)
        return deploy
    finally:
        c.close()


if __name__ == "__main__":
    main(sys.argv[1])
