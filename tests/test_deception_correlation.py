import json
from datetime import datetime, timezone

import pandas as pd

from src.deception.profiling import categorize, summarize
from src.utils import db
from tests.test_deception import FakeDecoyManager, add_detection, ctl, dcfg, decisions  # noqa: F401

SRC = "10.42.0.99"


def alert(cfg, severity="medium", kind="adaptive_rate", src=SRC, flows=8):
    with db.connect(db.db_path(cfg)) as c:
        db.insert_row(c, "behavior_alerts", src_ip=src, dst_ip="10.42.0.5", dst_port=1880, protocol=6, flows=flows,
                      rate_per_s=flows / 10, window_s=10.0, ml_malicious_flows=0, ml_classes="{}",
                      detected_at=datetime.now(timezone.utc).isoformat(), alert_type=kind, severity=severity,
                      threshold=5.0, baseline=1.0, details=json.dumps({"detector": "adaptive"}))


def interaction(cfg, src, profile, path, itype="page_request", n=1):
    with db.connect(db.db_path(cfg)) as c:
        for i in range(n):
            db.insert_row(c, "interactions", ts=f"2026-10-30T18:00:{i:02d}+00:00", decoy_name=f"decoy-{profile}",
                          decoy_profile=profile, pod="p", src_ip=src, src_port=40000 + i, method="GET",
                          path=path if itype != "unknown_path" else f"{path}{i}", status=200 if itype != "unknown_path" else 404,
                          interaction_type=itype, collected_at="2026-10-30T18:01:00+00:00")


def test_learned_threshold_alerts_alone_never_deploy(ctl, dcfg):
    for _ in range(4):                      # repeated medium alerts from one source
        alert(dcfg)
        ctl.run_cycle()
    d = decisions(dcfg)
    assert set(d["action"]) == {"await_evidence"} and not ctl.manager.decoys
    assert "suspicious behaviour only" in d["reason"].iloc[-1]


def test_repeated_learned_alerts_deploy_when_ml_corroboration_is_not_required(dcfg):
    from src.deception.controller import MapeKController

    dcfg["deception"]["thresholds"]["behavior_medium_requires_ml"] = False
    ctl = MapeKController(dcfg, manager=FakeDecoyManager())
    ctl.set_enabled(True)
    alert(dcfg)
    ctl.run_cycle()
    assert decisions(dcfg)["action"].tolist() == ["await_evidence"]
    alert(dcfg)  # second alert window from the same source and service
    ctl.run_cycle()
    assert set(decisions(dcfg)["action"].iloc[1:]) == {"deploy"}


def test_low_confidence_ml_does_not_corroborate(ctl, dcfg):
    add_detection(dcfg, "Node-RED Reconnaissance", 0.32)  # just above the decision threshold, below medium
    alert(dcfg)
    ctl.run_cycle()
    beh = decisions(dcfg).query("trigger == 'behavior'")
    assert set(beh["action"]) == {"await_evidence"} and not ctl.manager.decoys


def test_learned_threshold_alert_corroborated_by_ml(ctl, dcfg):
    add_detection(dcfg, "Node-RED Reconnaissance", 0.65)  # medium confidence, a single detection: not actionable alone
    alert(dcfg)
    ctl.run_cycle()
    d = decisions(dcfg)
    deploys = d[d["action"] == "deploy"]
    # one deployment per decoy for this source; whichever assessment comes first carries both kinds of evidence
    assert sorted(deploys["decoy_profile"]) == ["http-recon", "nodered"]
    corr = json.loads(deploys["evidence"].iloc[0])["correlation"]
    assert corr["detectors"] == ["behavior", "ml"]


def test_ml_and_behaviour_of_one_source_form_one_incident(ctl, dcfg):
    add_detection(dcfg, "Node-RED Reconnaissance", 0.95, n=3)
    alert(dcfg, severity="high", kind="flow_burst", flows=40)
    ctl.run_cycle()
    d = decisions(dcfg)
    deploys = d[d["action"] == "deploy"]
    assert sorted(deploys["decoy_profile"]) == ["http-recon", "nodered"]   # each decoy once
    assert sorted(ctl.manager.decoys) == ["decoy-http-recon", "decoy-nodered"]
    corr = json.loads(deploys["evidence"].iloc[0])["correlation"]
    assert corr["incident"] == f"src:{SRC}" and corr["detectors"] == ["behavior", "ml"]
    assert "ML and behavioural evidence" in deploys["reason"].iloc[0]


def test_profiles_prefer_decoys_the_source_engaged_with(ctl, dcfg):
    interaction(dcfg, SRC, "k8s-inventory", "/api/v1/namespaces", n=4)
    with db.connect(db.db_path(dcfg)) as c:
        order, why = ctl._profiles_for(c, {"trigger": "ml", "attack_class": "CVE-2022-23648", "src_ip": SRC,
                                           "target_port": None})
        other, _ = ctl._profiles_for(c, {"trigger": "ml", "attack_class": "CVE-2022-23648", "src_ip": "10.0.0.1",
                                         "target_port": None})
    assert order == ["k8s-inventory", "container-env"] and "source engaged before" in why
    assert other == ["k8s-inventory", "container-env"]   # engagement history of other sources also counts


def test_simulated_events_stay_outside_incidents(ctl, dcfg):
    ctl.submit_simulated_event("CVE-2019-5736", 0.99, src_ip=SRC)
    add_detection(dcfg, "Node-RED RCE", 0.95)
    ctl.run_cycle()
    d = decisions(dcfg)
    sim = d[d["simulated"] == 1]
    assert len(sim) == 1 and "correlation" not in json.loads(sim["evidence"].iloc[0])
    real = d[d["simulated"] == 0]
    assert json.loads(real["evidence"].iloc[0])["correlation"]["detectors"] == ["ml"]


def test_interaction_categories(cfg):
    p = cfg["deception"]["profiling"]
    assert categorize(2, 2, 0.0, 1, p) == "single_probe"
    assert categorize(26, 25, 0.8, 2, p) == "enumerating"
    assert categorize(10, 1, 0.0, 10, p) == "repeated_access"
    assert categorize(6, 4, 0.2, 2, p) == "exploring"


def test_summary_from_interaction_rows(cfg):
    rows = pd.DataFrame([
        {"ts": f"2026-10-30T18:00:{i:02d}+00:00", "decoy_name": "decoy-grafana", "decoy_profile": "grafana",
         "src_ip": "10.0.0.5", "method": "GET", "path": f"/x{i}", "status": 404, "interaction_type": "unknown_path",
         "decision_id": 7} for i in range(12)])
    s = summarize(rows, cfg["deception"]["profiling"])
    assert len(s) == 1 and s[0]["category"] == "enumerating" and s[0]["decision_ids"] == [7]
    assert s[0]["requests"] == 12 and s[0]["duration_s"] == 11.0 and s[0]["statuses"] == {"404": 12}


def test_unknown_flows_never_trigger_decoys(ctl, dcfg):
    from src.detection.unknown import UNKNOWN_CLASS

    pred = pd.DataFrame([{
        "flow_id": f"u{i}", "timestamp": None, "src_ip": SRC, "src_port": 41000 + i, "dst_ip": "10.42.0.5",
        "dst_port": 5555, "protocol": 6, "predicted_label": 2, "predicted_class": UNKNOWN_CLASS, "confidence": 0.99,
        "is_malicious": False, "capture_file": "w.pcap", "source": "pcap", "processing_time_ms": 1.0,
        "detected_at": datetime.now(timezone.utc).isoformat(), "true_label": None, "model": "test",
        "status": "unknown", "unknown_reason": "unfamiliar_service"} for i in range(5)])
    with db.connect(db.db_path(dcfg)) as c:
        db.insert_detections(c, pred)
    ctl.run_cycle()
    assert decisions(dcfg).empty and not ctl.manager.decoys
