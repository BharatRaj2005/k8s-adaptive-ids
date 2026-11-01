"""Attack Simulator: controlled traffic-generation Jobs started from the dashboard.

One run = one Kubernetes Job in the simulator namespace (ids-traffic), created from the
dataset-generation Job template with the generator v2 script, under the least-privilege
ids-attack-generator identity. Lifecycle of a run (persisted in simulation_runs):

  requested -> job_created -> pod_running -> traffic_generated -> pcap_captured -> conversion
  -> classification -> behavioural -> results_stored -> cleaned_up

* Capture: an already running capture is attached to and never stopped by the run; otherwise
  the run starts one and stops it (only that process) after its final window was processed.
* Ground truth: generator logs (every connection with its local port) are saved before the Job
  is deleted; detections and behavioural alerts involving the generator pod in the run's
  windows are tagged with the run id (real captured traffic, known origin).
* Cleanup: explicit deletion of the run's Job and Pods after completion, failure, cancellation
  or timeout, verified by listing; ttlSecondsAfterFinished as a backstop; recover() removes
  leftovers after a backend interruption. Only objects labelled with this framework's
  managed-by label (and the run's own id) are ever deleted.
* Only one run is active at a time.
"""
from __future__ import annotations

import copy
import json
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from src.backend import queries
from src.capture import service as capture_service
from src.datagen.session import parse_generator_log
from src.simulation.scenarios import ScenarioError, SimulationSpec, build_spec, catalog
from src.utils import db
from src.utils.config import load_config, project_path
from src.utils.logging_setup import get_logger

log = get_logger(__name__)
STAGES = [("requested", "Simulation requested"), ("job_created", "Kubernetes Job created"),
          ("pod_running", "Generator pod running"), ("traffic_generated", "Traffic generated"),
          ("pcap_captured", "PCAP captured"), ("conversion", "CICFlowMeter conversion"),
          ("classification", "ML classification"), ("behavioural", "Behavioural detection"),
          ("results_stored", "Results stored"), ("cleaned_up", "Generator cleaned up")]
ACTIVE = queries.ACTIVE_SIM_STATUSES
RUN_LABEL = "ids.lab/sim-run"
MANAGED_LABEL = "app.kubernetes.io/managed-by"
JSON_FIELDS = ("params", "stages", "capture_ids", "cleanup")
DONE = ("classified", "empty", "failed")


class SimulationError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime | None = None) -> str:
    return (t or _now()).isoformat()


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


class SimulationManager:
    def __init__(self, cfg: dict[str, Any] | None = None, batch=None, core=None, capture=capture_service,
                 poll_s: float = 1.0):
        self.cfg = cfg or load_config()
        self.s = self.cfg["simulator"]
        self.ns = self.s["namespace"]
        self.managed_by = self.s["managed_by"]
        self.batch, self.core = batch, core
        self.capture = capture
        self.poll_s = poll_s
        self.k8s_error: str | None = None
        self.run_dir = project_path(self.s["run_dir"])
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._cancel: dict[str, threading.Event] = {}

    # --- Kubernetes access ---------------------------------------------------------------
    def _api(self):
        if self.batch is None or self.core is None:
            try:
                from kubernetes import client, config as kconfig

                path = project_path(self.s["kubeconfig"])
                if not path.is_file():
                    raise FileNotFoundError(f"{path} missing; see kubernetes/simulator/README.md")
                api = kconfig.new_client_from_config(config_file=str(path))
                self.batch, self.core = client.BatchV1Api(api), client.CoreV1Api(api)
                self.k8s_error = None
            except Exception as e:
                self.k8s_error = str(e)[:300]
                raise SimulationError(f"Kubernetes unavailable for the simulator: {self.k8s_error}", 503)
        return self.batch, self.core

    def _selector(self, run_id: str | None = None) -> str:
        sel = f"{MANAGED_LABEL}={self.managed_by}"
        return f"{sel},{RUN_LABEL}={run_id}" if run_id else sel

    def _owned(self, obj, run_id: str | None = None) -> bool:
        labels = (obj.metadata.labels or {}) if hasattr(obj, "metadata") else obj["metadata"].get("labels", {})
        return labels.get(MANAGED_LABEL) == self.managed_by and (run_id is None or labels.get(RUN_LABEL) == run_id)

    # --- persistence ---------------------------------------------------------------------
    def _save(self, run_id: str, **fields) -> None:
        fields = {k: json.dumps(v, default=str) if k in JSON_FIELDS and v is not None else v for k, v in fields.items()}
        fields["updated_at"] = _iso()
        with db.connect(db.db_path(self.cfg)) as c:
            sets = ", ".join(f"{k} = ?" for k in fields)
            c.execute(f"UPDATE simulation_runs SET {sets} WHERE run_id = ?", [*map(db._clean, fields.values()), run_id])

    def _stage(self, run_id: str, stage: str, **fields) -> None:
        run = self.get(run_id) or {}
        stages = run.get("stages") or {}
        stages.setdefault(stage, _iso())
        self._save(run_id, stage=stage, stages=stages, **fields)
        log.info("simulation %s: %s", run_id, stage)

    def get(self, run_id: str) -> dict[str, Any] | None:
        run = queries.simulation_run(run_id, self.cfg)
        if run:
            run["stage_labels"] = STAGES
            run["thread_alive"] = bool(self._threads.get(run_id) and self._threads[run_id].is_alive())
        return run

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        return queries.simulation_runs(limit, self.cfg)

    def active(self) -> list[dict[str, Any]]:
        return [r for r in self.list(50) if r["status"] in ACTIVE]

    def scenarios(self) -> dict[str, Any]:
        out = catalog(self.cfg)
        out["stages"] = STAGES
        return out

    # --- start / cancel ------------------------------------------------------------------
    def start(self, category: str, scenario: str, target: str, duration_s=None, rate_per_s=None,
              max_requests=None) -> dict[str, Any]:
        try:
            spec = build_spec(category, scenario, target, duration_s, rate_per_s, max_requests, self.cfg)
        except ScenarioError as e:
            raise SimulationError(str(e), 422)
        with self._lock:
            active = self.active()
            if len(active) >= int(self.s["max_active"]):
                raise SimulationError(f"simulation {active[0]['run_id']} is still active; one run at a time", 409)
            batch, core = self._api()
            try:
                core.read_namespaced_config_map(self.s["configmap"], self.ns)
            except Exception as e:
                raise SimulationError(f"generator ConfigMap {self.s['configmap']} not readable in {self.ns}: "
                                      f"{str(e)[:150]}", 503)
            self._check_targets(core, spec)
            run_id = f"sim-{_now():%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
            scen = self.s["scenarios"].get(spec.category, {}).get(spec.scenario, {})
            expected = scen.get("class_label")
            if expected is None:
                expected = 2 if spec.category == "recon" else self.cfg["benign_label"] if spec.category == "benign" else None
            params = spec.to_dict()
            params["expected_class"] = expected
            params["expected_class_name"] = self.cfg["classes"].get(expected) if expected is not None else None
            with db.connect(db.db_path(self.cfg)) as c:
                db.insert_row(c, "simulation_runs", run_id=run_id, created_at=_iso(), updated_at=_iso(),
                              category=spec.category, profile=spec.profile, target=",".join(spec.apps),
                              params=json.dumps(params), status="requested", stage="requested",
                              stages=json.dumps({"requested": _iso()}))
            self._cancel[run_id] = threading.Event()
            t = threading.Thread(target=self._run, args=(run_id, spec), name=f"sim-{run_id}", daemon=True)
            self._threads[run_id] = t
            t.start()
        return self.get(run_id)

    def _check_targets(self, core, spec: SimulationSpec) -> None:
        from src.datagen.plan import load_datagen_config

        apps = load_datagen_config()["apps"]
        for app in spec.apps:
            c = apps[app]
            try:
                pods = core.list_namespaced_pod(c["namespace"], label_selector=c["pod_selector"]).items
            except Exception as e:
                raise SimulationError(f"cannot check target {app}: {str(e)[:150]}", 503)
            ready = [p for p in pods if p.status.phase == "Running"
                     and all(cs.ready for cs in (p.status.container_statuses or []))]
            if not ready:
                raise SimulationError(f"target application {app} has no ready pod", 409)

    def cancel(self, run_id: str) -> dict[str, Any]:
        run = self.get(run_id)
        if run is None:
            raise SimulationError(f"unknown run {run_id}", 404)
        if run["status"] not in ACTIVE or run_id not in self._cancel:
            raise SimulationError(f"run {run_id} is not active ({run['status']})", 409)
        self._cancel[run_id].set()
        self._save(run_id, error="cancellation requested")
        return self.get(run_id)

    # --- the run -------------------------------------------------------------------------
    def _job_manifest(self, run_id: str, spec: SimulationSpec) -> dict[str, Any]:
        job = copy.deepcopy(yaml.safe_load(project_path(self.s["job_template"]).read_text()))
        labels = {"app": "traffic-generator", "mode": "simulation", MANAGED_LABEL: self.managed_by, RUN_LABEL: run_id}
        job["metadata"].update(name=run_id, namespace=self.ns, labels=dict(labels))
        job["spec"]["ttlSecondsAfterFinished"] = int(self.s["ttl_seconds_after_finished"])
        job["spec"]["activeDeadlineSeconds"] = int(spec.duration_s) + 30
        pod = job["spec"]["template"]
        pod["metadata"]["labels"] = dict(labels)
        pod["spec"]["volumes"][0]["configMap"]["name"] = self.s["configmap"]
        # The generator runs as PID 1 without a SIGTERM handler, so it would ignore SIGTERM and keep sending
        # traffic for the default 30 s grace period after a cancel. Its log is flushed per line: kill promptly.
        pod["spec"]["terminationGracePeriodSeconds"] = 1
        env = pod["spec"]["containers"][0]["env"]
        env += [{"name": k, "value": v} for k, v in {**spec.env, "SESSION_ID": run_id}.items()]
        return job

    def _run(self, run_id: str, spec: SimulationSpec) -> None:
        cancel = self._cancel[run_id]
        owned_pid, status, error = None, "completed", None
        try:
            batch, core = self._api()
            self._save(run_id, status="running")
            with db.connect(db.db_path(self.cfg)) as c:
                baseline = c.execute("SELECT COALESCE(MAX(id), 0) FROM captures").fetchone()[0]
            state = self.capture.read_state(self.cfg)
            if state.get("running"):
                self._save(run_id, capture_owned=0, capture_pid=state.get("pid"))
            else:
                state = self.capture.start(None, True, self.cfg)
                owned_pid = state.get("pid")
                self._save(run_id, capture_owned=1, capture_pid=owned_pid)
            started = _now()
            if cancel.is_set():
                raise SimulationError("cancelled before the Job was created")
            batch.create_namespaced_job(self.ns, self._job_manifest(run_id, spec))
            self._stage(run_id, "job_created", job_name=run_id)

            pod = self._wait_pod(core, run_id, cancel)
            self._stage(run_id, "pod_running", pod_name=pod.metadata.name, pod_ip=pod.status.pod_ip)
            tag = lambda: self._tag(run_id, baseline, pod.status.pod_ip)   # noqa: E731 (live feed shows origin early)
            snap = lambda: self._snapshot_logs(core, run_id, pod.metadata.name)   # noqa: E731
            outcome = self._wait_job(batch, run_id, spec, cancel, tag, snap)
            if outcome != "succeeded":
                status = {"cancelled": "cancelled", "timeout": "timeout"}.get(outcome, "failed")
                error = {"cancelled": "cancelled by the user", "timeout": "generator exceeded its time limit"}.get(
                    outcome, "generator Job failed")
                self._delete_job(batch, run_id)          # stop traffic now; verified in cleanup below
                self._drain_logs(core, run_id, pod.metadata.name)   # keep reading until the pod is gone
            gen = self._collect_logs(core, run_id, pod.metadata.name)
            self._stage(run_id, "traffic_generated", requests=gen["requests"], connections=len(gen["connections"]),
                        traffic_start=gen["first_ts"], traffic_end=gen["last_ts"])
            self._save(run_id, status="processing")
            end = _parse(gen["last_ts"]) or _now()
            windows, note = self._wait_windows(run_id, baseline, started, end + timedelta(seconds=self.s["capture_tail_s"]),
                                               tag)
            self._store_results(run_id, windows, pod.status.pod_ip)
            if note:
                error = f"{error}; {note}" if error else note
        except SimulationError as e:
            status, error = ("cancelled" if cancel.is_set() else "failed"), str(e)
        except Exception as e:
            log.exception("simulation %s failed", run_id)
            status, error = "failed", f"{type(e).__name__}: {e}"
        finally:
            if owned_pid:
                self._stop_owned_capture(owned_pid)
            cleanup = self.cleanup(run_id)
            if cleanup.get("ok"):
                self._stage(run_id, "cleaned_up", cleanup=cleanup)
            else:
                self._save(run_id, cleanup=cleanup)
                error = f"{error}; cleanup incomplete" if error else "cleanup incomplete"
            self._save(run_id, status=status, error=error, finished_at=_iso())
            log.info("simulation %s finished: %s %s", run_id, status, error or "")

    def _wait_pod(self, core, run_id: str, cancel: threading.Event):
        deadline = time.monotonic() + self.s["pod_start_timeout_s"]
        while time.monotonic() < deadline:
            pods = core.list_namespaced_pod(self.ns, label_selector=self._selector(run_id)).items
            for p in pods:
                if p.status.pod_ip and p.status.phase in ("Running", "Succeeded", "Failed"):
                    return p
            if cancel.is_set():
                raise SimulationError("cancelled before the generator pod started")
            time.sleep(self.poll_s)
        raise SimulationError(f"generator pod did not start within {self.s['pod_start_timeout_s']} s")

    def _tag(self, run_id: str, baseline: int, pod_ip: str | None) -> None:
        """Mark generator-pod flows of windows processed since the run started (refined in _store_results)."""
        if not pod_ip:
            return
        with db.connect(db.db_path(self.cfg)) as c:
            c.execute("UPDATE detections SET sim_run_id = ? WHERE capture_id > ? AND (src_ip = ? OR dst_ip = ?) "
                      "AND sim_run_id IS NULL", (run_id, baseline, pod_ip, pod_ip))
            c.execute("UPDATE behavior_alerts SET sim_run_id = ? WHERE capture_id > ? AND (src_ip = ? OR dst_ip = ?) "
                      "AND sim_run_id IS NULL", (run_id, baseline, pod_ip, pod_ip))

    def _wait_job(self, batch, run_id: str, spec: SimulationSpec, cancel: threading.Event, tag=None,
                  snapshot=None) -> str:
        deadline = time.monotonic() + spec.duration_s + 90
        polls = 0
        while time.monotonic() < deadline:
            if tag:
                tag()
            if snapshot and polls % 3 == 0:
                snapshot()
            polls += 1
            if cancel.is_set():
                return "cancelled"
            st = batch.read_namespaced_job_status(run_id, self.ns).status
            if st.succeeded:
                return "succeeded"
            if st.failed:
                reasons = {c.reason for c in (st.conditions or [])}
                return "timeout" if "DeadlineExceeded" in reasons else "failed"
            time.sleep(self.poll_s)
        return "timeout"

    def _snapshot_logs(self, core, run_id: str, pod_name: str) -> bool:
        """Save the pod's current log; never replaces a longer saved log with a shorter (or no) one."""
        path = self.run_dir / f"{run_id}.log.jsonl"
        try:
            text = core.read_namespaced_pod_log(pod_name, self.ns)
        except Exception:
            return False
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if not path.is_file() or len(text) >= path.stat().st_size:
            path.write_text(text)
        return True

    def _drain_logs(self, core, run_id: str, pod_name: str) -> None:
        """After a stop request: keep saving the log until the pod is gone (its last requests included)."""
        deadline = time.monotonic() + self.s["cleanup_timeout_s"]
        while time.monotonic() < deadline and self._snapshot_logs(core, run_id, pod_name):
            time.sleep(self.poll_s)

    def _collect_logs(self, core, run_id: str, pod_name: str) -> dict[str, Any]:
        """Generator log (ground truth): read from the pod if it still exists, else the last saved snapshot."""
        if not self._snapshot_logs(core, run_id, pod_name):
            log.warning("logs of %s unavailable; using the last snapshot", pod_name)
        path = self.run_dir / f"{run_id}.log.jsonl"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if not path.is_file():
            path.write_text("")
        text = path.read_text()
        gen = parse_generator_log(text)
        (self.run_dir / f"{run_id}.connections.json").write_text(json.dumps(gen["connections"], indent=1))
        self._save(run_id, log_file=f"{self.s['run_dir']}/{run_id}.log.jsonl")
        return gen

    def _wait_windows(self, run_id: str, baseline: int, started: datetime, until: datetime,
                      tag=None) -> tuple[list[dict], str | None]:
        """Wait until a processed capture window covers `until` and every window of the run is processed."""
        deadline = time.monotonic() + self.s["result_timeout_s"] + max(0.0, (until - _now()).total_seconds())
        reached: set[str] = set()
        while True:
            if tag:
                tag()
            with db.connect(db.db_path(self.cfg)) as c:
                rows = [dict(r) for r in c.execute(
                    "SELECT id, started_at, ended_at, status, csv_file, flows, packets FROM captures WHERE id > ? "
                    "ORDER BY id", (baseline,))]
            rows = [r for r in rows if (_parse(r["ended_at"]) or _now()) >= started - timedelta(seconds=1)
                    and (_parse(r["started_at"]) or _now()) <= until]
            covered = any((_parse(r["ended_at"]) or started) >= until for r in rows)
            for stage, ok in (("pcap_captured", covered),
                              ("conversion", covered and all(r["csv_file"] or r["status"] in DONE for r in rows)),
                              ("classification", covered and all(r["status"] in DONE for r in rows)),
                              ("behavioural", covered and all(r["status"] in DONE for r in rows))):
                if ok and stage not in reached:
                    reached.add(stage)
                    self._stage(run_id, stage, capture_ids=[r["id"] for r in rows])
            if covered and all(r["status"] in DONE for r in rows):
                return rows, None
            if not self.capture.read_state(self.cfg).get("running") and not covered:
                done = [r for r in rows if r["status"] in DONE]
                if all(r["status"] in DONE for r in rows):
                    return done, "capture stopped before the end of the generated traffic (results are partial)"
            if time.monotonic() > deadline:
                return [r for r in rows if r["status"] in DONE], \
                    f"final capture window not processed within {self.s['result_timeout_s']} s (results are partial)"
            time.sleep(self.poll_s)

    def _store_results(self, run_id: str, windows: list[dict], pod_ip: str | None) -> None:
        ids = [int(w["id"]) for w in windows]
        counts = {"detections": 0, "attacks": 0, "unknown": 0, "alerts": 0}
        if ids and pod_ip:
            marks = ",".join("?" * len(ids))
            with db.connect(db.db_path(self.cfg)) as c:
                c.execute(f"UPDATE detections SET sim_run_id = ? WHERE capture_id IN ({marks}) AND "
                          f"(src_ip = ? OR dst_ip = ?) AND sim_run_id IS NULL", (run_id, *ids, pod_ip, pod_ip))
                c.execute(f"UPDATE behavior_alerts SET sim_run_id = ? WHERE capture_id IN ({marks}) AND "
                          f"(src_ip = ? OR dst_ip = ?)", (run_id, *ids, pod_ip, pod_ip))
                row = c.execute("SELECT COUNT(*), SUM(COALESCE(status, CASE WHEN is_malicious = 1 THEN 'attack' "
                                "ELSE 'benign' END) = 'attack'), SUM(status = 'unknown') FROM detections "
                                "WHERE sim_run_id = ?", (run_id,)).fetchone()
                counts = {"detections": row[0] or 0, "attacks": row[1] or 0, "unknown": row[2] or 0,
                          "alerts": c.execute("SELECT COUNT(*) FROM behavior_alerts WHERE sim_run_id = ?",
                                              (run_id,)).fetchone()[0]}
        self._stage(run_id, "results_stored", capture_ids=ids, flows=sum(w.get("flows") or 0 for w in windows),
                    packets=sum(w.get("packets") or 0 for w in windows), **counts)

    def _stop_owned_capture(self, pid: int) -> None:
        """Stop the capture only if it is still the process this run started."""
        try:
            state = self.capture.read_state(self.cfg)
            if state.get("running") and state.get("pid") == pid:
                self.capture.stop(self.cfg)
        except Exception:
            log.exception("stopping the run's capture failed")

    # --- cleanup -------------------------------------------------------------------------
    def _delete_job(self, batch, run_id: str) -> list[str]:
        deleted = []
        for j in batch.list_namespaced_job(self.ns, label_selector=self._selector(run_id)).items:
            if self._owned(j, run_id):
                batch.delete_namespaced_job(j.metadata.name, self.ns, propagation_policy="Foreground")
                deleted.append(j.metadata.name)
        return deleted

    def cleanup(self, run_id: str) -> dict[str, Any]:
        """Delete the run's Job and Pods (labels verified) and confirm nothing is left."""
        out: dict[str, Any] = {"ok": False, "jobs_deleted": [], "pods_deleted": [], "remaining": []}
        try:
            batch, core = self._api()
            out["jobs_deleted"] = self._delete_job(batch, run_id)
            deadline = time.monotonic() + self.s["cleanup_timeout_s"]
            while True:
                jobs = [j.metadata.name for j in batch.list_namespaced_job(
                    self.ns, label_selector=self._selector(run_id)).items]
                pods = [p for p in core.list_namespaced_pod(self.ns, label_selector=self._selector(run_id)).items
                        if self._owned(p, run_id)]
                if not jobs and not pods:
                    break
                if time.monotonic() > deadline:
                    for p in pods:      # foreground deletion did not finish: remove the run's pods directly
                        core.delete_namespaced_pod(p.metadata.name, self.ns)
                        out["pods_deleted"].append(p.metadata.name)
                    out["remaining"] = jobs + [p.metadata.name for p in pods]
                    break
                time.sleep(self.poll_s)
            out["ok"] = not out["remaining"]
        except Exception as e:
            out["error"] = str(e)[:300]
        out["verified_at"] = _iso()
        return out

    def cleanup_status(self, run_id: str) -> dict[str, Any]:
        batch, core = self._api()
        jobs = [j.metadata.name for j in batch.list_namespaced_job(self.ns, label_selector=self._selector(run_id)).items]
        pods = [p.metadata.name for p in core.list_namespaced_pod(self.ns, label_selector=self._selector(run_id)).items]
        run = self.get(run_id) or {}
        return {"run_id": run_id, "jobs": jobs, "pods": pods, "clean": not jobs and not pods,
                "recorded_cleanup": run.get("cleanup"), "checked_at": _iso()}

    def logs(self, run_id: str, tail: int = 200) -> dict[str, Any]:
        run = self.get(run_id)
        if run is None:
            raise SimulationError(f"unknown run {run_id}", 404)
        path = self.run_dir / f"{run_id}.log.jsonl"
        if path.is_file():
            lines, source = path.read_text().splitlines(), "saved"
        elif run["status"] in ACTIVE and run.get("pod_name"):
            _, core = self._api()
            lines, source = core.read_namespaced_pod_log(run["pod_name"], self.ns).splitlines(), "pod"
        else:
            lines, source = [], "none"
        return {"run_id": run_id, "source": source, "lines": lines[-int(tail):], "total_lines": len(lines)}

    def _finalize_interrupted(self, run: dict[str, Any]) -> str | None:
        """What the dead run thread would have done: save the log, stop the traffic, let the run's own capture
        finish, and tag the generator-pod flows of every window since the run started."""
        rid, pod_name, pod_ip = run["run_id"], run.get("pod_name"), run.get("pod_ip")
        notes = []
        try:
            batch, core = self._api()
            if pod_name:
                self._snapshot_logs(core, rid, pod_name)
                self._delete_job(batch, rid)
                self._drain_logs(core, rid, pod_name)
                gen = self._collect_logs(core, rid, pod_name)
                self._stage(rid, "traffic_generated", requests=gen["requests"], connections=len(gen["connections"]),
                            traffic_start=gen["first_ts"], traffic_end=gen["last_ts"])
        except Exception as e:
            notes.append(f"log collection failed: {str(e)[:120]}")
        if run.get("capture_owned") and run.get("capture_pid"):
            self._stop_owned_capture(int(run["capture_pid"]))      # processes its remaining windows first
        if pod_ip:
            with db.connect(db.db_path(self.cfg)) as c:
                windows = [dict(r) for r in c.execute(
                    "SELECT id, flows, packets FROM captures WHERE ended_at >= ? AND status IN "
                    f"({','.join('?' * len(DONE))}) ORDER BY id", (run["created_at"], *DONE))]
            if windows:                     # the capture service processed them while the backend was down
                for stage in ("pcap_captured", "conversion", "classification", "behavioural"):
                    self._stage(rid, stage, capture_ids=[w["id"] for w in windows])
            self._store_results(rid, windows, pod_ip)
            if not run.get("capture_owned") and self.capture.read_state(self.cfg).get("running"):
                notes.append("capture still running: windows processed after recovery are not tagged")
        return "; ".join(notes) or None

    def recover(self) -> dict[str, Any]:
        """After a backend interruption: close runs left active, delete leftover Jobs/Pods, stop owned captures."""
        report: dict[str, Any] = {"interrupted": [], "orphans": [], "errors": []}
        for run in self.active():
            rid = run["run_id"]
            if self._threads.get(rid) and self._threads[rid].is_alive():
                continue
            note = self._finalize_interrupted(run)
            cleanup = self.cleanup(rid)
            if cleanup.get("ok"):
                self._stage(rid, "cleaned_up")
            self._save(rid, status="interrupted", finished_at=_iso(), cleanup=cleanup,
                       error="backend interrupted during the run; finalised by recovery" + (f" ({note})" if note else ""))
            report["interrupted"].append(rid)
        try:
            batch, _ = self._api()
            for j in batch.list_namespaced_job(self.ns, label_selector=self._selector()).items:
                rid = (j.metadata.labels or {}).get(RUN_LABEL)
                alive = rid in self._threads and self._threads[rid].is_alive()
                if rid and not alive and self._owned(j):
                    report["orphans"].append({"run_id": rid, **self.cleanup(rid)})
        except Exception as e:
            report["errors"].append(str(e)[:300])
        if report["interrupted"] or report["orphans"]:
            log.info("simulation recovery: %s", report)
        return report
