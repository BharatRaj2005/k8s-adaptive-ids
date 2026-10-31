"""Attack Simulator: scenario validation, Job manifests, lifecycle, cleanup, capture coordination, recovery.

Kubernetes and the capture service are replaced by in-memory fakes; the SQLite database is a temporary
copy of the schema. No Job is created on a real cluster by these tests.
"""
from __future__ import annotations

import copy
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pandas as pd
import pytest

from src.simulation import manager as M
from src.simulation.scenarios import ScenarioError, build_spec, catalog
from src.utils import db

POD_IP = "10.42.0.77"


# --- fakes -------------------------------------------------------------------------------------
def _match(labels: dict, selector: str | None) -> bool:
    if not selector:
        return True
    return all(labels.get(k) == v for k, v in (p.split("=", 1) for p in selector.split(",")))


def _obj(name, labels, **status):
    return NS(metadata=NS(name=name, labels=labels), status=NS(**status))


class FakeBatch:
    def __init__(self, outcome="succeeded", polls=2):
        self.jobs, self.outcome, self.polls, self.deleted = {}, outcome, polls, []
        self.created = []

    def create_namespaced_job(self, ns, body):
        self.created.append(body)
        self.jobs[body["metadata"]["name"]] = {"body": body, "polls": 0}

    def read_namespaced_job_status(self, name, ns):
        j = self.jobs[name]
        j["polls"] += 1
        done = j["polls"] >= self.polls
        return NS(status=NS(succeeded=1 if done and self.outcome == "succeeded" else None,
                            failed=1 if done and self.outcome in ("failed", "timeout") else None,
                            conditions=[NS(reason="DeadlineExceeded")] if self.outcome == "timeout" else []))

    def list_namespaced_job(self, ns, label_selector=None):
        return NS(items=[_obj(n, j["body"]["metadata"]["labels"]) for n, j in self.jobs.items()
                         if _match(j["body"]["metadata"]["labels"], label_selector)])

    def delete_namespaced_job(self, name, ns, propagation_policy=None):
        self.deleted.append(name)
        self.jobs.pop(name, None)


class FakeCore:
    def __init__(self, batch, targets_ready=True):
        self.batch, self.targets_ready = batch, targets_ready
        self.extra_pods: list = []          # pods not created by the simulator
        self.deleted_pods = []

    def read_namespaced_config_map(self, name, ns):
        return NS(metadata=NS(name=name))

    def _sim_pods(self):
        return [_obj(f"{n}-abcde", j["body"]["spec"]["template"]["metadata"]["labels"], pod_ip=POD_IP, phase="Running")
                for n, j in self.batch.jobs.items()]

    def list_namespaced_pod(self, ns, label_selector=None):
        if ns == "target-apps":
            return NS(items=[NS(status=NS(phase="Running" if self.targets_ready else "Pending",
                                          container_statuses=[NS(ready=self.targets_ready)]))])
        return NS(items=[p for p in self._sim_pods() + self.extra_pods if _match(p.metadata.labels, label_selector)])

    def read_namespaced_pod_log(self, name, ns):
        if not any(name.startswith(j) for j in self.batch.jobs):
            raise RuntimeError("404 pod not found")              # pod deleted together with its Job
        now = datetime.now(timezone.utc).isoformat()
        return "\n".join(json.dumps(e) for e in [
            {"ev": "start", "ts": now}, {"ev": "conn_open", "cid": 1, "app": "nodered", "lport": 40001, "peer": "x", "ts": now},
            {"ev": "req", "cid": 1, "app": "nodered", "method": "GET", "path": "/admin", "status": 404, "ts": now},
            {"ev": "conn_close", "cid": 1, "app": "nodered", "requests": 1, "ts": now}, {"ev": "end", "ts": now}])

    def delete_namespaced_pod(self, name, ns):
        self.deleted_pods.append(name)


class FakeCapture:
    """Capture service stand-in; while running it writes processed windows with flows of the generator pod."""

    def __init__(self, cfg, running=False):
        self.cfg, self.running, self.started, self.stopped = cfg, running, 0, 0
        self.pid = 4242 if running else None
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._windows, daemon=True)
        self._t.start()

    def read_state(self, cfg=None):
        return {"running": self.running, "pid": self.pid, "status": "running" if self.running else "stopped"}

    def start(self, windows, process, cfg=None):
        self.running, self.pid, self.started = True, 5151, self.started + 1
        return self.read_state()

    def stop(self, cfg=None):
        self.running, self.stopped = False, self.stopped + 1
        return self.read_state()

    def _windows(self):
        i = 0
        while not self._stop.is_set():
            if self.running:
                i += 1
                start = datetime.now(timezone.utc)
                time.sleep(0.3)
                end = datetime.now(timezone.utc)
                with db.connect(db.db_path(self.cfg)) as c:
                    cid = db.upsert_capture(c, f"w{i}-{start.timestamp()}.pcap", started_at=start.isoformat(),
                                            ended_at=end.isoformat(), status="classified", csv_file="x.csv",
                                            flows=3, packets=30, duration_s=0.3)
                    pred = pd.DataFrame([
                        {"src_ip": POD_IP, "dst_ip": "10.42.0.45", "dst_port": 1880, "predicted_label": 2,
                         "predicted_class": "Node-RED Reconnaissance", "confidence": 0.9, "is_malicious": True,
                         "source": "pcap", "detected_at": end.isoformat(), "status": "attack"},
                        {"src_ip": "10.42.0.45", "dst_ip": POD_IP, "dst_port": 40001, "predicted_label": 0,
                         "predicted_class": "Benign", "confidence": 0.9, "is_malicious": False, "source": "pcap",
                         "detected_at": end.isoformat(), "status": "benign"},
                        {"src_ip": "10.42.0.1", "dst_ip": "10.42.0.45", "dst_port": 1880, "predicted_label": 0,
                         "predicted_class": "Benign", "confidence": 0.9, "is_malicious": False, "source": "pcap",
                         "detected_at": end.isoformat(), "status": "benign"}])
                    db.insert_detections(c, pred, capture_id=cid)
                    db.insert_row(c, "behavior_alerts", capture_id=cid, src_ip=POD_IP, dst_port=1880, flows=20,
                                  detected_at=end.isoformat())
            else:
                time.sleep(0.05)

    def close(self):
        self._stop.set()


@pytest.fixture
def sim_cfg(cfg, tmp_path):
    c = copy.deepcopy(cfg)
    c["database"]["path"] = str(tmp_path / "ids.sqlite")
    s = c["simulator"]
    s.update(run_dir=str(tmp_path / "runs"), capture_tail_s=0, result_timeout_s=10, cleanup_timeout_s=2,
             pod_start_timeout_s=3)
    return c


def _manager(sim_cfg, outcome="succeeded", capture_running=False, polls=2, targets_ready=True):
    batch = FakeBatch(outcome, polls)
    core = FakeCore(batch, targets_ready)
    cap = FakeCapture(sim_cfg, capture_running)
    return M.SimulationManager(sim_cfg, batch=batch, core=core, capture=cap, poll_s=0.05), batch, core, cap


def _wait(mgr, run_id, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        run = mgr.get(run_id)
        if run["status"] not in M.ACTIVE and not run["thread_alive"]:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run did not finish: {mgr.get(run_id)}")


# --- scenarios ---------------------------------------------------------------------------------
def test_catalog_lists_all_scanners_and_targets(cfg):
    c = catalog(cfg)
    assert set(c["categories"]["recon"]) == {"sequential", "shuffled", "threaded", "slow", "keepalive", "multi_app"}
    assert set(c["targets"]) == {"nodered", "grafana", "influxdb"}


@pytest.mark.parametrize("kw, msg", [
    ({"category": "exploit", "scenario": "sequential", "target": "nodered"}, "unknown scenario"),
    ({"category": "recon", "scenario": "rce", "target": "nodered"}, "unknown scenario"),
    ({"category": "recon", "scenario": "sequential", "target": "kube-apiserver"}, "not an allowed"),
    ({"category": "recon", "scenario": "sequential", "target": "http://evil"}, "not an allowed"),
    ({"category": "recon", "scenario": "sequential", "target": "nodered", "rate_per_s": 500}, "rate_per_s"),
    ({"category": "recon", "scenario": "sequential", "target": "nodered", "duration_s": 3600}, "duration_s"),
    ({"category": "recon", "scenario": "sequential", "target": "nodered", "max_requests": 10**6}, "max_requests"),
    ({"category": "recon", "scenario": "sequential", "target": "nodered", "rate_per_s": "nan"}, "rate_per_s"),
])
def test_invalid_requests_are_rejected(cfg, kw, msg):
    with pytest.raises(ScenarioError, match=msg):
        build_spec(cfg=cfg, **kw)


def test_rate_maps_to_generator_spacing(cfg):
    s = build_spec("recon", "threaded", "grafana", 30, 8, 100, cfg=cfg)
    assert s.env["WORKERS"] == "4" and float(s.env["DELAY_MIN"]) == pytest.approx(0.5)
    assert s.env["TARGET_APPS"] == "grafana" and s.env["MAX_SECONDS"] == "30" and s.env["REQUESTS"] == "100"
    sweep = build_spec("recon", "multi_app", "all", cfg=cfg)
    assert sweep.apps == ["nodered", "grafana", "influxdb"]
    assert all(".target-apps.svc.cluster.local" in u for u in sweep.env["APP_URLS"].split(","))


# --- manifest ----------------------------------------------------------------------------------
def test_job_manifest_labels_limits_and_hardening(sim_cfg):
    mgr, *_ = _manager(sim_cfg)
    spec = build_spec("recon", "sequential", "nodered", 40, 5, 100, cfg=sim_cfg)
    job = mgr._job_manifest("sim-x", spec)
    labels = job["metadata"]["labels"]
    assert labels[M.MANAGED_LABEL] == "ids-attack-generator" and labels[M.RUN_LABEL] == "sim-x"
    assert job["spec"]["template"]["metadata"]["labels"] == labels
    assert job["metadata"]["namespace"] == "ids-traffic"
    assert job["spec"]["ttlSecondsAfterFinished"] == 300 and job["spec"]["activeDeadlineSeconds"] == 70
    pod = job["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False and pod["restartPolicy"] == "Never"
    assert pod["terminationGracePeriodSeconds"] == 1          # cancel stops traffic promptly (PID 1 ignores SIGTERM)
    c = pod["containers"][0]
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"] and c["securityContext"]["readOnlyRootFilesystem"]
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["PROFILE"] == "seq_wordlist" and env["SESSION_ID"] == "sim-x"


# --- lifecycle ---------------------------------------------------------------------------------
def test_full_lifecycle_with_owned_capture(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg)
    try:
        run = mgr.start("recon", "sequential", "nodered", 20, 5, 50)
        done = _wait(mgr, run["run_id"])
    finally:
        cap.close()
    assert done["status"] == "completed", done["error"]
    assert list(done["stages"]) == [k for k, _ in M.STAGES]
    assert done["pod_ip"] == POD_IP and done["requests"] == 1 and done["capture_owned"] == 1
    assert cap.started == 1 and cap.stopped == 1                     # started for the run, stopped afterwards
    assert batch.deleted == [run["run_id"]] and not batch.jobs and done["cleanup"]["ok"]
    with db.connect(db.db_path(sim_cfg)) as c:
        tagged = c.execute("SELECT src_ip, dst_ip FROM detections WHERE sim_run_id = ?", (run["run_id"],)).fetchall()
        untagged = c.execute("SELECT COUNT(*) FROM detections WHERE sim_run_id IS NULL AND src_ip = '10.42.0.1'").fetchone()[0]
    assert tagged and all(POD_IP in (r[0], r[1]) for r in tagged) and untagged >= 1
    assert done["attacks"] >= 1 and done["alerts"] >= 1 and done["capture_ids"]
    assert (mgr.run_dir / f"{run['run_id']}.log.jsonl").is_file()     # logs kept after the Job is gone


def test_attaches_to_running_capture_without_stopping_it(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg, capture_running=True)
    try:
        done = _wait(mgr, mgr.start("benign", "browse", "grafana", 20, 1, 10)["run_id"])
    finally:
        cap.close()
    assert done["status"] == "completed" and done["capture_owned"] == 0
    assert cap.started == 0 and cap.stopped == 0 and cap.running


def test_only_one_active_run(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg, polls=10**6)
    try:
        run = mgr.start("recon", "sequential", "nodered", 20, 5, 50)
        with pytest.raises(M.SimulationError) as e:
            mgr.start("recon", "shuffled", "grafana")
        assert e.value.status_code == 409
        mgr.cancel(run["run_id"])
        _wait(mgr, run["run_id"])
    finally:
        cap.close()


def test_cancel_collects_logs_then_cleans_up(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg, polls=10**6)
    try:
        run = mgr.start("recon", "keepalive", "influxdb", 60, 5, 100)
        while "pod_running" not in (mgr.get(run["run_id"])["stages"] or {}):
            time.sleep(0.05)
        mgr.cancel(run["run_id"])
        done = _wait(mgr, run["run_id"])
    finally:
        cap.close()
    assert done["status"] == "cancelled" and "cancelled" in done["error"]
    assert "traffic_generated" in done["stages"] and (mgr.run_dir / f"{run['run_id']}.log.jsonl").is_file()
    assert not batch.jobs and done["cleanup"]["ok"] and cap.stopped == 1


@pytest.mark.parametrize("outcome, status", [("timeout", "timeout"), ("failed", "failed")])
def test_failed_or_timed_out_job_is_cleaned_up(sim_cfg, outcome, status):
    mgr, batch, core, cap = _manager(sim_cfg, outcome=outcome)
    try:
        done = _wait(mgr, mgr.start("recon", "slow", "nodered", 30, 0.5, 20)["run_id"])
    finally:
        cap.close()
    assert done["status"] == status and not batch.jobs and done["cleanup"]["ok"]


def test_target_not_ready_is_refused(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg, targets_ready=False)
    try:
        with pytest.raises(M.SimulationError) as e:
            mgr.start("recon", "sequential", "nodered")
        assert e.value.status_code == 409 and not batch.created
    finally:
        cap.close()


def test_recovery_cleans_only_simulator_objects(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg)
    try:
        with db.connect(db.db_path(sim_cfg)) as c:          # a run left active by a previous backend process
            db.insert_row(c, "simulation_runs", run_id="sim-old", created_at="2026-10-31T00:00:00+00:00",
                          category="recon", profile="seq_wordlist", target="nodered", status="running",
                          capture_owned=1, capture_pid=999)
        mine = {"app": "traffic-generator", M.MANAGED_LABEL: "ids-attack-generator", M.RUN_LABEL: "sim-old"}
        orphan = {**mine, M.RUN_LABEL: "sim-lost"}
        foreign = {"app": "traffic-generator", "mode": "recon"}        # e.g. kubectl create -f recon-job.yaml
        for name, labels in (("sim-old", mine), ("sim-lost", orphan), ("traffic-recon-x", foreign)):
            batch.jobs[name] = {"body": {"metadata": {"name": name, "labels": labels},
                                         "spec": {"template": {"metadata": {"labels": labels}}}}, "polls": 0}
        core.extra_pods.append(_obj("target-pod", {"app": "nodered"}, pod_ip="10.42.0.45", phase="Running"))
        rep = mgr.recover()
    finally:
        cap.close()
    assert rep["interrupted"] == ["sim-old"] and [o["run_id"] for o in rep["orphans"]] == ["sim-lost"]
    assert set(batch.jobs) == {"traffic-recon-x"} and not core.deleted_pods
    assert mgr.get("sim-old")["status"] == "interrupted" and cap.stopped == 0   # pid 999 is not our capture


def test_cleanup_status_reports_leftovers(sim_cfg):
    mgr, batch, core, cap = _manager(sim_cfg)
    try:
        labels = {M.MANAGED_LABEL: "ids-attack-generator", M.RUN_LABEL: "sim-y"}
        batch.jobs["sim-y"] = {"body": {"metadata": {"name": "sim-y", "labels": labels},
                                        "spec": {"template": {"metadata": {"labels": labels}}}}, "polls": 0}
        st = mgr.cleanup_status("sim-y")
        assert not st["clean"] and st["jobs"] == ["sim-y"]
        assert mgr.cleanup("sim-y")["ok"] and mgr.cleanup_status("sim-y")["clean"]
    finally:
        cap.close()


def test_recovery_finalises_an_interrupted_run(sim_cfg):
    """Backend died while the Job ran: recovery saves the log, deletes the Job, stops the run's own capture,
    tags the generator flows of the run's windows and records the run as interrupted."""
    mgr, batch, core, cap = _manager(sim_cfg, capture_running=True)
    cap.pid = 777                                           # the capture this run started before the backend died
    try:
        created = datetime.now(timezone.utc) - timedelta(seconds=30)
        labels = {"app": "traffic-generator", M.MANAGED_LABEL: "ids-attack-generator", M.RUN_LABEL: "sim-int"}
        batch.jobs["sim-int"] = {"body": {"metadata": {"name": "sim-int", "labels": labels},
                                          "spec": {"template": {"metadata": {"labels": labels}}}}, "polls": 0}
        with db.connect(db.db_path(sim_cfg)) as c:
            db.insert_row(c, "simulation_runs", run_id="sim-int", created_at=created.isoformat(), category="recon",
                          profile="seq_wordlist", target="nodered", status="running", stage="pod_running",
                          stages=json.dumps({s: created.isoformat() for s in ("requested", "job_created", "pod_running")}),
                          capture_owned=1, capture_pid=777,
                          pod_name="sim-int-abcde", pod_ip=POD_IP)
        time.sleep(0.8)                                      # the fake capture writes windows with generator flows
        rep = mgr.recover()
    finally:
        cap.close()
    run = mgr.get("sim-int")
    assert rep["interrupted"] == ["sim-int"] and run["status"] == "interrupted"
    assert not batch.jobs and run["cleanup"]["ok"] and cap.stopped == 1
    assert (mgr.run_dir / "sim-int.log.jsonl").read_text() and run["requests"] == 1
    assert list(run["stages"]) == [k for k, _ in M.STAGES]       # every stage recorded, in order
    assert run["detections"] >= 2 and run["attacks"] >= 1
