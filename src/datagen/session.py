"""Run one generation session end to end.

    capture start (dedicated tcpdump on cni0) -> generator Job -> wait -> pod logs ->
    capture stop -> Job cleanup -> CICFlowMeter -> CSV validation -> session manifest

Every outcome, including failures, is written to manifests/<session>.json. A failed
step sets status "failed" with the error; nothing is dropped silently.
"""
from __future__ import annotations

import json
import signal
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from src.capture.tcpdump import _parse_counts, build_command
from src.datagen import kube
from src.datagen.plan import Session, output_dir
from src.feature_extraction.cicflowmeter import convert_pcap
from src.preprocessing.schema import DST_IP, DST_PORT, FLOW_ID, PROTOCOL, SRC_IP, SRC_PORT, TIMESTAMP, \
    parse_timestamps, read_flow_csv
from src.utils.config import get_path, load_config
from src.utils.logging_setup import get_logger

log = get_logger(__name__)
SUBDIRS = ("raw", "pcaps", "flows", "labelled", "manifests", "reports")
META_COLUMNS = [FLOW_ID, SRC_IP, SRC_PORT, DST_IP, DST_PORT, PROTOCOL, TIMESTAMP, "Flow Duration"]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def dirs(dcfg: dict[str, Any]) -> dict[str, Path]:
    root = output_dir(dcfg)
    out = {d: root / d for d in SUBDIRS}
    for p in out.values():
        p.mkdir(parents=True, exist_ok=True)
    return out


def parse_generator_log(text: str) -> dict[str, Any]:
    """Connections (with local ports), request statistics and the session time window."""
    events = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    conns: dict[int, dict[str, Any]] = {}
    reqs = [e for e in events if e.get("ev") == "req"]
    for e in events:
        if e.get("ev") == "conn_open":
            conns[e["cid"]] = {"cid": e["cid"], "app": e["app"], "lport": e["lport"], "peer": e["peer"],
                               "open": e["ts"], "close": None, "requests": 0}
        elif e.get("ev") == "conn_close" and e.get("cid") in conns:
            conns[e["cid"]].update(close=e["ts"], requests=e.get("requests", 0))
    times = [e["ts"] for e in events if e.get("ev") in ("conn_open", "req", "conn_close")]
    end = next((e for e in events if e.get("ev") == "end"), {})
    return {
        "events": len(events),
        "connections": list(conns.values()),
        "requests": len(reqs),
        "request_errors": sum(1 for r in reqs if "error" in r),
        "conn_errors": sum(1 for e in events if e.get("ev") == "conn_error"),
        "status_counts": dict(Counter(str(r.get("status", "error")) for r in reqs)),
        "method_counts": dict(Counter(r["method"] for r in reqs)),
        "app_counts": dict(Counter(r["app"] for r in reqs)),
        "distinct_paths": len({r["path"] for r in reqs}),
        "first_ts": min(times) if times else None,
        "last_ts": max(times) if times else None,
        "completed": bool(end),
    }


def validate_csv(path: Path, required_features: list[str]) -> dict[str, Any]:
    """Structural checks of a CICFlowMeter CSV; problems are reported, not fixed."""
    df = read_flow_csv(path)
    missing = [c for c in META_COLUMNS + required_features if c not in df.columns]
    ts = parse_timestamps(df[TIMESTAMP]) if TIMESTAMP in df.columns else pd.Series(dtype="datetime64[ns]")
    feats = [c for c in required_features if c in df.columns]
    num = df[feats].apply(pd.to_numeric, errors="coerce") if feats else pd.DataFrame()
    return {
        "rows": int(len(df)), "columns": int(len(df.columns)), "missing_columns": missing,
        "unparseable_timestamps": int(ts.isna().sum()),
        "negative_duration": int((pd.to_numeric(df.get("Flow Duration"), errors="coerce") < 0).sum())
        if "Flow Duration" in df.columns else None,
        "rows_all_features_nan": int(num.isna().all(axis=1).sum()) if len(num.columns) else None,
        "first_flow": str(ts.min()) if len(ts) else None, "last_flow": str(ts.max()) if len(ts) else None,
        "valid": not missing and len(df) > 0,
    }


def model_features(cfg: dict[str, Any]) -> list[str]:
    schema = get_path("models_dir", cfg) / cfg["detection"]["active_model"] / "feature_schema.json"
    return json.loads(schema.read_text())["input_features"] if schema.is_file() else []


class Capture:
    """A tcpdump process for the whole session (same command builder as the capture service)."""

    def __init__(self, path: Path, cfg: dict[str, Any]):
        c = cfg["capture"]
        self.part = path.with_name(path.name + ".part")
        self.path = path
        self.cmd = build_command(c["tcpdump"], c["interface"], self.part, c.get("snaplen", 0), "")
        self.proc: subprocess.Popen | None = None
        self.started_at = self.ended_at = None

    def start(self) -> None:
        self.proc = subprocess.Popen(self.cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.started_at = now()
        time.sleep(0.5)
        if self.proc.poll() is not None:
            raise RuntimeError(f"tcpdump exited: {self.proc.stderr.read().strip()[-300:]}")

    def stop(self) -> dict[str, Any]:
        if self.proc is None:
            return {}
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
        try:
            _, err = self.proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        self.ended_at = now()
        packets, dropped = _parse_counts(err or "")
        if self.part.exists():
            self.part.rename(self.path)
        self.proc = None
        return {"pcap": self.path.name, "interface": self.cmd[2], "started_at": self.started_at,
                "ended_at": self.ended_at, "packets": packets, "dropped": dropped,
                "bytes": self.path.stat().st_size if self.path.exists() else None}


def _wait_job(name: str, ns: str, lim: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Wait until the Job finishes; returns (job status, pod)."""
    deadline = time.monotonic() + lim["max_session_seconds"] + lim["job_start_timeout_s"] + 30
    pod: dict[str, Any] = {}
    while time.monotonic() < deadline:
        job = kube.kjson("-n", ns, "get", "job", name)
        pods = kube.kjson("-n", ns, "get", "pods", "-l", f"job-name={name}")["items"]
        if pods:
            pod = pods[0]
        st = job.get("status", {})
        if st.get("succeeded") or st.get("failed"):
            return st, pod
        time.sleep(1)
    raise TimeoutError(f"job {name} did not finish in time")


def run_session(s: Session, dcfg: dict[str, Any], cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    d = dirs(dcfg)
    ns, lim = dcfg["kubernetes"]["namespace"], dcfg["limits"]
    name = kube.job_name(s.session_id)
    pcap = d["pcaps"] / f"{s.session_id}.pcap"
    meta: dict[str, Any] = {"dataset_version": dcfg["dataset_version"], **s.to_dict(), "job": name,
                            "status": "running", "error": None, "started_at": now()}
    manifest_path = d["manifests"] / f"{s.session_id}.json"
    cap = Capture(pcap, cfg)
    try:
        try:
            kube.kubectl("-n", ns, "delete", "job", name, "--ignore-not-found", "--wait=true", timeout=90)
        except kube.KubeError:
            pass
        meta["targets"] = kube.app_endpoints(dcfg)
        meta["benign_generator_ips"] = kube.selector_ips(ns, dcfg["kubernetes"]["benign_generator_selector"])
        cap.start()
        time.sleep(lim["capture_lead_seconds"])
        kube.kubectl("apply", "-f", "-", stdin=yaml.safe_dump(kube.job_manifest(s, dcfg)))
        meta["job_created_at"] = now()
        status, pod = _wait_job(name, ns, lim)
        meta["job_status"] = {k: status.get(k) for k in ("succeeded", "failed", "startTime", "completionTime")}
        meta["pod"] = {"name": pod.get("metadata", {}).get("name"), "ip": pod.get("status", {}).get("podIP"),
                       "node": pod.get("spec", {}).get("nodeName"), "phase": pod.get("status", {}).get("phase")}
        logs = kube.kubectl("-n", ns, "logs", meta["pod"]["name"], timeout=60) if meta["pod"]["name"] else ""
        (d["raw"] / f"{s.session_id}.log.jsonl").write_text(logs)
        gen = parse_generator_log(logs)
        meta["generator"] = {k: v for k, v in gen.items() if k != "connections"}
        (d["raw"] / f"{s.session_id}.connections.json").write_text(json.dumps(gen["connections"], indent=1))
        meta["connections_file"] = f"raw/{s.session_id}.connections.json"
        if gen["last_ts"]:
            waited = (datetime.now(timezone.utc) - datetime.fromisoformat(gen["last_ts"])).total_seconds()
            time.sleep(max(0.0, lim["capture_tail_seconds"] - waited))
        meta["capture"] = cap.stop()
        (d["raw"] / f"{s.session_id}.pods.json").write_text(json.dumps(kube.pod_ip_map(), indent=1))
        kube.kubectl("-n", ns, "delete", "job", name, "--ignore-not-found", "--wait=false")
        meta["job_deleted"] = True

        problems = []
        if status.get("failed"):
            problems.append("generator Job failed")
        if not meta["pod"]["ip"]:
            problems.append("pod IP unknown")
        if not gen["completed"]:
            problems.append("generator did not log its end event")
        if not gen["connections"]:
            problems.append("generator opened no connection")
        size_mb = (meta["capture"].get("bytes") or 0) / 1e6
        if size_mb > lim["max_pcap_mb"]:
            problems.append(f"capture {size_mb:.0f} MB exceeds {lim['max_pcap_mb']} MB")

        conv = convert_pcap(pcap, out_dir=d["flows"], cfg=cfg)
        meta["conversion"] = conv.to_dict()
        if conv.status != "converted":
            problems.append(f"CICFlowMeter {conv.status}: {conv.error}")
        else:
            meta["flows_csv"] = f"flows/{Path(conv.csv).name}"
            meta["validation"] = validate_csv(Path(conv.csv), model_features(cfg))
            if not meta["validation"]["valid"]:
                problems.append(f"CSV invalid: missing {meta['validation']['missing_columns'][:5]}")
        meta["status"] = "failed" if problems else "ok"
        meta["error"] = "; ".join(problems) or None
    except Exception as e:  # recorded, never swallowed
        log.exception("session %s failed", s.session_id)
        meta["status"], meta["error"] = "failed", f"{type(e).__name__}: {e}"
        if cap.proc is not None:
            meta["capture"] = cap.stop()
        try:
            kube.kubectl("-n", ns, "delete", "job", name, "--ignore-not-found", "--wait=false")
        except Exception:
            pass
    meta["finished_at"] = now()
    manifest_path.write_text(json.dumps(meta, indent=2, default=str))
    log.info("session %s: %s %s", s.session_id, meta["status"], meta["error"] or "")
    return meta
