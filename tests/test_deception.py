import copy
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from src.deception.controller import MapeKController
from src.deception.k8s_decoys import DecoyError, DecoyManager, decoy_name
from src.utils import db
from src.utils.config import PROJECT_ROOT

DECOY_DIR = PROJECT_ROOT / "kubernetes" / "deception"


class FakeDecoyManager:
    """In-memory stand-in for DecoyManager (same interface)."""

    def __init__(self, ready=True):
        self.decoys, self.lines, self.ready, self.calls = {}, {}, ready, []

    def deploy(self, profile, replicas=1):
        name = decoy_name(profile)
        if name in self.decoys:
            raise DecoyError(f"{name} already exists")
        self.decoys[name] = {"name": name, "profile": profile, "replicas": replicas}
        self.calls.append(("deploy", name))
        return {"name": name, "service_ip": "10.43.9.9", "port": 80}

    def scale(self, name, replicas):
        self.decoys[name]["replicas"] = replicas
        self.calls.append(("scale", name, replicas))

    def remove(self, name):
        self.calls.append(("remove", name))
        return self.decoys.pop(name, None) is not None

    def list_decoys(self):
        return {n: {**d, "ready_replicas": d["replicas"] if self.ready else 0} for n, d in self.decoys.items()}

    def interaction_lines(self, name, since_seconds):
        return [(f"{name}-pod", rec) for rec in self.lines.get(name, [])]


@pytest.fixture
def dcfg(cfg, tmp_path):
    c = copy.deepcopy(cfg)
    c["database"]["path"] = str(tmp_path / "ids.sqlite")
    c["deception"]["cooldown_seconds"] = 0
    c["deception"]["redeploy_cooldown_seconds"] = 0
    return c


@pytest.fixture
def ctl(dcfg):
    c = MapeKController(dcfg, manager=FakeDecoyManager())
    c.set_enabled(True)
    return c


def add_detection(cfg, cls, conf, src="10.42.0.99", n=1, source="pcap"):
    label = {v: k for k, v in cfg["classes"].items()}[cls]
    pred = pd.DataFrame([{
        "flow_id": f"f{i}", "timestamp": None, "src_ip": src, "src_port": 40000 + i, "dst_ip": "10.42.0.5",
        "dst_port": 1880, "protocol": 6, "predicted_label": label, "predicted_class": cls, "confidence": conf,
        "is_malicious": label != 0, "capture_file": "w.pcap", "source": source, "processing_time_ms": 1.0,
        "detected_at": datetime.now(timezone.utc).isoformat(), "true_label": None, "model": "test"} for i in range(n)])
    with db.connect(db.db_path(cfg)) as c:
        db.insert_detections(c, pred)


def decisions(cfg):
    with db.connect(db.db_path(cfg)) as c:
        return db.query_df(c, "SELECT * FROM decisions ORDER BY id")


def decoys(cfg):
    with db.connect(db.db_path(cfg)) as c:
        return db.query_df(c, "SELECT * FROM decoys ORDER BY id")


# --- policy ---------------------------------------------------------------------------

def test_policy_covers_every_attack_class(cfg):
    d = cfg["deception"]
    attack_classes = {v for k, v in cfg["classes"].items() if k != cfg["benign_label"]}
    assert set(d["attack_policy"]) == attack_classes
    for profiles in list(d["attack_policy"].values()) + list(d["behavior_policy"].values()):
        assert profiles and all(p in d["profiles"] for p in profiles)


def test_decoy_profiles_exist_in_server_content(cfg):
    content = json.loads((DECOY_DIR / "profiles.json").read_text())
    assert set(cfg["deception"]["profiles"]) == set(content)


# --- analyze / plan -------------------------------------------------------------------

def test_benign_and_low_confidence_do_not_deploy(ctl, dcfg):
    add_detection(dcfg, "CVE-2019-20933", 0.4)
    ctl.run_cycle()
    d = decisions(dcfg)
    assert d["action"].tolist() == ["monitor"] and "below" in d["reason"][0]
    assert ctl.manager.calls == []


def test_medium_confidence_needs_repeated_evidence(ctl, dcfg):
    add_detection(dcfg, "CVE-2019-20933", 0.7)
    ctl.run_cycle()
    assert decisions(dcfg)["action"].tolist() == ["await_evidence"]
    add_detection(dcfg, "CVE-2019-20933", 0.7, n=2)  # now 3 in the repeat window
    ctl.run_cycle()
    last = decisions(dcfg).iloc[-1]
    assert last["action"] == "deploy" and last["decoy_profile"] == "influxdb" and "confirmed" in last["reason"]


def test_high_confidence_deploys_mapped_decoy_once(ctl, dcfg):
    add_detection(dcfg, "CVE-2021-43798", 0.95)
    ctl.run_cycle()
    add_detection(dcfg, "CVE-2021-43798", 0.97)
    ctl.run_cycle()
    acts = decisions(dcfg)[["action", "decoy_profile", "result"]].values.tolist()
    assert acts == [["deploy", "grafana", "ok"], ["refresh", "grafana", "ok"]]  # duplicate prevented
    assert ctl.manager.calls == [("deploy", "decoy-grafana")]
    assert decoys(dcfg)["status"].tolist() == ["active"]  # ready on the next housekeeping pass


def test_max_active_decoys_enforced(dcfg):
    dcfg["deception"]["max_active_decoys"] = 1
    ctl = MapeKController(dcfg, manager=FakeDecoyManager())
    ctl.set_enabled(True)
    add_detection(dcfg, "CVE-2021-43798", 0.95)
    add_detection(dcfg, "CVE-2019-20933", 0.95, src="10.42.0.98")
    ctl.run_cycle()
    assert sorted(decisions(dcfg)["action"]) == ["deploy", "suppress_limit"]


def test_deployment_cooldown(dcfg):
    dcfg["deception"]["cooldown_seconds"] = 300
    ctl = MapeKController(dcfg, manager=FakeDecoyManager())
    ctl.set_enabled(True)
    add_detection(dcfg, "CVE-2021-43798", 0.95)
    ctl.run_cycle()
    add_detection(dcfg, "CVE-2019-20933", 0.95)
    ctl.run_cycle()
    assert decisions(dcfg)["action"].tolist() == ["deploy", "suppress_cooldown"]


def _burst(dcfg, src="10.42.0.181"):
    with db.connect(db.db_path(dcfg)) as c:
        db.insert_row(c, "behavior_alerts", src_ip=src, dst_ip="10.42.0.177", dst_port=1880, protocol=6,
                      flows=40, rate_per_s=4.0, window_s=10.0, ml_malicious_flows=0, ml_classes="{}",
                      detected_at=datetime.now(timezone.utc).isoformat())


def test_flow_burst_alone_never_deploys(ctl, dcfg):
    # A fixed-rule flow burst with no ML evidence (fast/bursty benign looks like this) must not act.
    for _ in range(3):
        _burst(dcfg)
        ctl.run_cycle()
    d = decisions(dcfg)
    assert set(d["action"]) == {"await_evidence"} and not ctl.manager.decoys
    assert "awaiting ML corroboration" in d["reason"].iloc[-1]


def test_flow_burst_deploys_service_specific_decoys_and_scales(ctl, dcfg):
    # With ML corroboration from the same source, the flow burst deploys service-specific decoys and scales.
    add_detection(dcfg, "Node-RED Reconnaissance", 0.95, src="10.42.0.181", n=3)
    _burst(dcfg)
    ctl.run_cycle()
    assert set(ctl.manager.decoys) == {"decoy-http-recon", "decoy-nodered"}
    deploys = decisions(dcfg).query("action == 'deploy'")
    assert deploys["reason"].str.contains("ML and behavioural evidence").any()   # corroboration recorded
    _burst(dcfg); _burst(dcfg)  # three burst windows from the same source
    ctl.run_cycle()
    assert ctl.manager.decoys["decoy-http-recon"]["replicas"] == 2


def test_simulated_events_are_labelled_and_separate(ctl, dcfg):
    ctl.submit_simulated_event("CVE-2019-5736", 0.99, src_ip="192.0.2.1", note="demo")
    ctl.run_cycle()
    d = decisions(dcfg).iloc[0]
    assert d["simulated"] == 1 and d["reason"].startswith("SIMULATED") and d["decoy_profile"] == "container-env"
    assert decoys(dcfg)["simulated"].tolist() == [1]
    with db.connect(db.db_path(dcfg)) as c:
        assert c.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0
    with pytest.raises(ValueError):
        ctl.submit_simulated_event("Not A Class", 0.9)


def test_disabled_controller_takes_no_decisions(dcfg):
    ctl = MapeKController(dcfg, manager=FakeDecoyManager())
    ctl.set_enabled(False)
    add_detection(dcfg, "CVE-2021-43798", 0.99)
    ctl.run_cycle()
    assert decisions(dcfg).empty and ctl.manager.calls == []
    ctl.set_enabled(True)  # evidence from before enabling is not replayed
    ctl.run_cycle()
    assert decisions(dcfg).empty


# --- lifecycle --------------------------------------------------------------------------

def test_readiness_interactions_and_ttl(ctl, dcfg):
    add_detection(dcfg, "CVE-2019-20933", 0.95)
    ctl.run_cycle()
    ctl.run_cycle()
    row = decoys(dcfg).iloc[0]
    assert row["status"] == "active" and row["deploy_seconds"] >= 0
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "profile": "influxdb", "src_ip": "10.42.0.50", "src_port": 5555,
           "method": "GET", "path": "/query", "query": "", "user_agent": "x", "status": 401,
           "type": "page_request", "body_bytes": 0}
    ctl.manager.lines["decoy-influxdb"] = [rec]
    ctl.run_cycle()
    ctl.run_cycle()  # same log line again: stored once
    with db.connect(db.db_path(dcfg)) as c:
        ints = db.query_df(c, "SELECT * FROM interactions")
    assert len(ints) == 1
    assert ints["decoy_id"][0] == row["id"] and ints["decision_id"][0] == row["decision_id"]
    assert ints["detection_id"][0] == row["detection_id"]
    # force expiry
    with db.connect(db.db_path(dcfg)) as c:
        c.execute("UPDATE decoys SET expires_at = ?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
    ctl.run_cycle()
    assert decoys(dcfg)["status"].tolist() == ["expired"]
    assert decisions(dcfg).iloc[-1][["trigger", "action"]].tolist() == ["ttl", "remove"]
    assert ("remove", "decoy-influxdb") in ctl.manager.calls


def test_manual_deploy_and_remove(ctl, dcfg):
    res = ctl.manual_deploy("k8s-inventory")
    assert res["result"] == "ok"
    with pytest.raises(DecoyError):
        ctl.manual_deploy("k8s-inventory")
    with pytest.raises(DecoyError):
        ctl.manual_deploy("not-a-profile")
    assert ctl.manual_remove("decoy-k8s-inventory")["result"] == "ok"
    assert decoys(dcfg)["status"].tolist() == ["removed"]
    assert decisions(dcfg)["trigger"].tolist() == ["manual", "manual"]


def test_kubernetes_unavailable_is_recorded_not_fatal(dcfg):
    def boom():
        raise DecoyError("cluster unreachable")
    ctl = MapeKController(dcfg, manager_factory=boom)
    ctl.set_enabled(True)
    add_detection(dcfg, "CVE-2021-43798", 0.99)
    summary = ctl.run_cycle()
    assert "cluster unreachable" in summary["housekeeping"]["error"]
    d = decisions(dcfg).iloc[0]
    assert d["action"] == "deploy" and d["result"] == "failed" and "cluster unreachable" in d["reason"]
    assert ctl.status()["kubernetes_available"] is False


# --- manifests --------------------------------------------------------------------------

def test_decoy_template_is_hardened(cfg):
    from kubernetes import client

    mgr = DecoyManager(cfg, api_client=client.ApiClient())
    dep, svc = mgr.render("grafana", 2)
    spec = dep["spec"]["template"]["spec"]
    ctr = spec["containers"][0]
    assert dep["metadata"]["name"] == "decoy-grafana" and dep["spec"]["replicas"] == 2
    assert spec["automountServiceAccountToken"] is False and spec["securityContext"]["runAsNonRoot"] is True
    assert ctr["securityContext"]["readOnlyRootFilesystem"] is True
    assert ctr["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert ctr["securityContext"]["allowPrivilegeEscalation"] is False
    for forbidden in ("hostNetwork", "hostPID", "hostIPC"):
        assert not spec.get(forbidden)
    assert all("hostPath" not in v for v in spec["volumes"])
    assert svc["spec"]["ports"][0]["port"] == 3000
    with pytest.raises(DecoyError):
        mgr.render("grafana", 99)
    with pytest.raises(DecoyError):
        mgr.render("evil; rm", 1)


# --- decoy server -----------------------------------------------------------------------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_decoy_server_serves_synthetic_content_and_logs(tmp_path):
    port, hport = _free_port(), _free_port()
    env = {"PROFILE": "http-recon", "DECOY_NAME": "decoy-test", "PORT": str(port), "HEALTH_PORT": str(hport),
           "PROFILES_FILE": str(DECOY_DIR / "profiles.json"), "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen([sys.executable, str(DECOY_DIR / "decoy_server.py")], env=env,
                            stdout=subprocess.PIPE, text=True)
    try:
        assert json.loads(proc.stdout.readline())["event"] == "started"
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{hport}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        assert b"Operations Portal" in urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read()
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nothing-here", timeout=2)
        assert e.value.code == 404
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/login", data=b"user=a", method="POST"),
                               timeout=2)
        lines = [json.loads(proc.stdout.readline()) for _ in range(3)]
    finally:
        proc.terminate()
        proc.wait(5)
    assert [(l["method"], l["path"], l["type"]) for l in lines] == [
        ("GET", "/", "page_request"), ("GET", "/nothing-here", "unknown_path"), ("POST", "/login", "data_submission")]
    assert all(l["src_ip"] == "127.0.0.1" and l["decoy"] == "decoy-test" for l in lines)
    assert lines[2]["body_bytes"] == 6
