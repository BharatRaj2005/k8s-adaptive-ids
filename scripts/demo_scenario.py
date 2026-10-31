"""Repeatable end-to-end demonstration against the live lab (backend must be running).

    .venv/bin/python scripts/demo_scenario.py [--api http://127.0.0.1:8000] [--benign-windows 3]

Steps follow the project brief: cluster and targets -> benign traffic captured and
classified (no decoys) -> controlled reconnaissance -> detection -> MAPE-K decision
-> decoy deployment -> decoy interaction -> stored records -> cleanup, plus a
clearly labelled simulated event for an attack class that cannot be generated
safely. Results are written to reports/deception_test_report.md from what was
actually observed; a failed check is reported as failed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "KUBECONFIG": os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))}


class Demo:
    def __init__(self, api: str):
        self.api = api.rstrip("/")
        self.steps: list[dict] = []
        self.facts: dict = {}

    def get(self, path, **params):
        r = requests.get(self.api + path, params=params, timeout=60)
        r.raise_for_status()
        return r.json()

    def post(self, path, body=None):
        r = requests.post(self.api + path, json=body or {}, timeout=120)
        r.raise_for_status()
        return r.json()

    def kubectl(self, *args) -> str:
        return subprocess.run(["kubectl", *args], env=ENV, capture_output=True, text=True, check=True).stdout.strip()

    def step(self, title: str, ok: bool, detail: str):
        self.steps.append({"step": len(self.steps) + 1, "title": title, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {len(self.steps):2d}. {title}: {detail}", flush=True)

    def wait(self, fn, timeout: float, every: float = 3.0):
        end = time.time() + timeout
        while time.time() < end:
            v = fn()
            if v:
                return v
            time.sleep(every)
        return None

    def run_job(self, manifest: str) -> tuple[str, str]:
        job = self.kubectl("create", "-f", str(ROOT / manifest), "-o", "name")
        self.kubectl("-n", "ids-traffic", "wait", "--for=condition=complete", job, "--timeout=300s")
        name = job.split("/", 1)[1]
        pod = self.kubectl("-n", "ids-traffic", "get", "pods", "-l", f"job-name={name}",
                           "-o", "jsonpath={.items[0].metadata.name}")
        ip = self.kubectl("-n", "ids-traffic", "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
        n = sum('"status"' in line for line in self.kubectl("-n", "ids-traffic", "logs", pod).splitlines())
        return name, ip if n else ip

    # ------------------------------------------------------------------------------------
    def run(self, benign_windows: int):
        started = datetime.now(timezone.utc)
        self.facts["started_at"] = started.isoformat()

        k = self.get("/api/kubernetes/status")
        nodes = k.get("nodes", [])
        self.step("Kubernetes cluster running", k.get("connected") and all(n["ready"] == "True" for n in nodes),
                  f"connected={k.get('connected')}, nodes={[(n['name'], n['ready'], n['version']) for n in nodes]}")
        tpods = k.get("namespaces", {}).get("target-apps", {}).get("pods", [])
        self.step("Target applications ready", len(tpods) >= 3 and all(p["ready"] for p in tpods),
                  ", ".join(f"{p['name']}={p['phase']}" for p in tpods))
        gen = [p for p in k.get("namespaces", {}).get("ids-traffic", {}).get("pods", [])
               if p["labels"].get("mode") == "benign"]
        self.step("Benign traffic generator running", bool(gen) and gen[0]["ready"],
                  f"{gen[0]['name']} ip={gen[0]['ip']}" if gen else "not found")

        # clean slate for the deception part of the demo
        for d in self.get("/api/deception/status")["active_decoys"]:
            requests.delete(f"{self.api}/api/deception/decoys/{d['name']}", timeout=60)
        self.post("/api/deception/enable")
        last_decision = max([a["id"] for a in self.get("/api/deception/actions", limit=1)] or [0])
        last_capture = max([c["id"] for c in self.get("/api/captures", limit=1)] or [0])

        # benign phase
        self.post("/api/capture/start", {"windows": benign_windows, "process": True})
        self.wait(lambda: not self.get("/api/capture/status")["service"]["running"], 60 + 15 * benign_windows)
        caps = [c for c in self.get("/api/captures", limit=50) if c["id"] > last_capture]
        flows = sum(c["flows"] or 0 for c in caps)
        mal = [d for d in self.get("/api/detections", limit=5000, source="pcap")
               if d["capture_id"] in {c["id"] for c in caps}]
        n_mal = sum(d["is_malicious"] for d in mal)
        self.step("Benign traffic captured and classified",
                  len(caps) == benign_windows and all(c["status"] in ("classified", "empty") for c in caps),
                  f"{len(caps)} windows, {flows} flows, {n_mal} predicted malicious, "
                  f"conversion {[round(c['conversion_s'] or 0, 2) for c in caps]} s, "
                  f"pipeline {[round(c['pipeline_s'] or 0, 2) for c in caps]} s")
        self.post("/api/deception/cycle")
        deploys = [a for a in self.get("/api/deception/actions", limit=500)
                   if a["id"] > last_decision and a["action"] in ("deploy", "scale")]
        self.step("Benign traffic does not activate decoys", not deploys,
                  f"deploy/scale decisions during benign phase: {len(deploys)}")
        self.facts["benign_phase"] = {"windows": len(caps), "flows": flows, "ml_malicious": n_mal}

        # reconnaissance phase
        last_capture = max(c["id"] for c in caps) if caps else last_capture
        last_alert = max([a["id"] for a in self.get("/api/alerts", limit=1)] or [0])
        self.post("/api/capture/start", {"process": True})
        time.sleep(8)
        job, recon_ip = self.run_job("kubernetes/traffic-generator/recon-job.yaml")
        self.step("Controlled reconnaissance generated (isolated lab)", True, f"Job {job}, attacker pod IP {recon_ip}")
        alerts = self.wait(lambda: [a for a in self.get("/api/alerts", limit=200)
                                    if a["id"] > last_alert and a["src_ip"] == recon_ip], 60)
        self.post("/api/capture/stop")
        rdet = [d for d in self.get("/api/detections", limit=5000, src_ip=recon_ip, source="pcap")
                if (d["capture_id"] or 0) > last_capture]
        ml_mal = [d for d in rdet if d["is_malicious"]]
        self.step("Malicious activity detected",
                  bool(alerts),
                  f"{len(alerts or [])} behavioural alerts from {recon_ip} "
                  f"({ {t: sum((x.get('alert_type') or 'flow_burst') == t for x in alerts or []) for t in sorted({x.get('alert_type') or 'flow_burst' for x in alerts or []})} }, "
                  f"max {max([a['flows'] for a in alerts or []] or [0])} flows/window); per-flow ML: "
                  f"{len(ml_mal)}/{len(rdet)} attacker flows predicted malicious "
                  f"(reported as measured, not adjusted)")
        self.facts["recon"] = {"job": job, "attacker_ip": recon_ip, "burst_alerts": len(alerts or []),
                               "attacker_flows": len(rdet), "ml_malicious": len(ml_mal)}

        decs = self.wait(lambda: [a for a in self.get("/api/deception/actions", limit=500)
                                  if a["id"] > last_decision and a["action"] == "deploy" and a["src_ip"] == recon_ip], 30)
        self.step("MAPE-K controller chose decoys", bool(decs),
                  "; ".join(f"{a['decoy_profile']} ({a['trigger']}, {a['result']}): {a['reason']}" for a in decs or []))

        def active():
            st = self.get("/api/deception/status")["active_decoys"]
            return st if st and all(d["status"] == "active" for d in st) else None
        act = self.wait(active, 150) or []
        self.step("Decoys deployed and healthy", bool(act),
                  ", ".join(f"{d['name']} replicas={d['replicas']} ready in {d['deploy_seconds']:.1f}s, "
                            f"expires {d['expires_at'][11:19]}Z" for d in act))
        self.facts["decoys"] = [{k: d[k] for k in ("name", "profile", "replicas", "deploy_seconds", "service_ip")}
                                for d in act]

        before = len(self.get("/api/deception/interactions", limit=5000))
        pjob, probe_ip = self.run_job("kubernetes/traffic-generator/decoy-probe-job.yaml")
        ints = self.wait(lambda: [i for i in self.get("/api/deception/interactions", limit=5000)
                                  if i["src_ip"] == probe_ip] or None, 60)
        by_decoy: dict = {}
        for i in ints or []:
            by_decoy.setdefault(i["decoy_name"], {}).setdefault(i["interaction_type"], 0)
            by_decoy[i["decoy_name"]][i["interaction_type"]] += 1
        linked = all(i["decision_id"] for i in ints or [])
        self.step("Decoy interactions logged", bool(ints) and linked,
                  f"Job {pjob} from {probe_ip}: {len(ints or [])} interactions {by_decoy}; "
                  f"all linked to a decision: {linked}; total before {before}")
        self.facts["interactions"] = {"probe_ip": probe_ip, "count": len(ints or []), "by_decoy": by_decoy}

        m = self.get("/api/metrics")
        self.step("Records available to the dashboard", m["total_interactions"] >= len(ints or []) and m["decisions"] > 0,
                  f"metrics: flows={m['total_flows']}, malicious={m['malicious_flows']}, bursts={m['flow_bursts']}, "
                  f"active decoys={m['active_decoys']}, interactions={m['total_interactions']}, decisions={m['decisions']}")

        # simulated event for an attack that cannot be generated safely
        sim = self.post("/api/deception/test-event", {"attack_class": "CVE-2019-5736", "confidence": 0.97,
                                                       "src_ip": "192.0.2.66", "note": "demo: runc escape cannot be run safely"})
        self.post("/api/deception/cycle")
        sdec = [a for a in self.get("/api/deception/actions", limit=50) if a["simulated"] == 1 and a["id"] > last_decision]
        self.step("Simulated test event handled and labelled", bool(sdec) and all(a["reason"].startswith("SIMULATED") for a in sdec),
                  f"event {sim['simulated_event_id']}: " + "; ".join(f"{a['action']} {a['decoy_profile']} ({a['result']})" for a in sdec))

        # cleanup
        names = [d["name"] for d in self.get("/api/deception/status")["active_decoys"]]
        for n in names:
            requests.delete(f"{self.api}/api/deception/decoys/{n}", timeout=60).raise_for_status()
        time.sleep(3)
        left = self.kubectl("-n", "ids-deception", "get", "deploy,svc", "-l",
                            "app.kubernetes.io/managed-by=ids-deception-controller", "-o", "name")
        self.step("Decoy cleanup", not left, f"removed {names}; remaining managed resources: {left or 'none'}")
        self.post("/api/deception/disable")
        self.facts["finished_at"] = datetime.now(timezone.utc).isoformat()

    def report(self) -> Path:
        out = ROOT / "reports" / "deception_test_report.md"
        ok = sum(s["ok"] for s in self.steps)
        lines = [
            "# Deception Testing Report", "",
            f"Generated by `scripts/demo_scenario.py` on {self.facts.get('finished_at', '')[:19]} UTC against the live "
            "K3s lab. Every line below is an observed result.", "",
            f"**{ok} / {len(self.steps)} checks passed.**", "",
            "| # | Check | Result | Observed |", "|---|---|---|---|",
        ]
        for s in self.steps:
            lines.append(f"| {s['step']} | {s['title']} | {'PASS' if s['ok'] else 'FAIL'} | {s['detail'].replace('|', '/')} |")
        lines += ["", "## Facts", "", "```json", json.dumps(self.facts, indent=2), "```", "",
                  "## Notes", "",
                  "- Reconnaissance is detected by the per-source flow-burst detector; per-flow ML results for the "
                  "attacker's flows are reported as measured. See `reports/model_evaluation.md` for why single "
                  "reconnaissance flows are not separable from benign requests in this lab.",
                  "- The simulated event exercises the controller for an attack (runc container escape) that must "
                  "not be executed. It is stored in `simulated_events`, never in `detections`, and every resulting "
                  "decision is marked `simulated` with a reason starting `SIMULATED`.",
                  "- Decoys are reached through their own service names; no production traffic is redirected.", ""]
        out.write_text("\n".join(lines))
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.environ.get("IDS_API_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--benign-windows", type=int, default=3)
    args = ap.parse_args()
    demo = Demo(args.api)
    try:
        demo.run(args.benign_windows)
    except Exception as e:
        demo.step("Scenario aborted", False, f"{type(e).__name__}: {e}")
        try:
            demo.post("/api/capture/stop")
        except Exception:
            pass
    print("report:", demo.report())
    sys.exit(0 if all(s["ok"] for s in demo.steps) else 1)


if __name__ == "__main__":
    main()
