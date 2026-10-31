import copy
import importlib
import shutil

import pytest
import yaml
from fastapi.testclient import TestClient

from src.utils import config as config_mod
from tests.conftest import FIXTURES, requires_dataset


@pytest.fixture(scope="module")
def api(tmp_path_factory, cfg):
    tmp = tmp_path_factory.mktemp("api")
    c = copy.deepcopy(cfg)
    c["database"]["path"] = str(tmp / "ids.sqlite")
    c["paths"]["pcap_dir"] = str(tmp / "pcap")
    c["paths"]["flows_dir"] = str(tmp / "flows")
    c["capture"]["pid_file"] = str(tmp / "capture.pid")
    c["capture"]["state_file"] = str(tmp / "state.json")
    c["deception"]["kubeconfig"] = str(tmp / "missing.kubeconfig")  # Kubernetes deliberately unavailable
    c["simulator"]["kubeconfig"] = str(tmp / "missing.kubeconfig")
    c["simulator"]["run_dir"] = str(tmp / "runs")
    (tmp / "pcap").mkdir()
    (tmp / "flows").mkdir()
    cfg_file = tmp / "settings.yaml"
    cfg_file.write_text(yaml.safe_dump(c))
    mp = pytest.MonkeyPatch()
    mp.setenv("IDS_CONFIG", str(cfg_file))
    config_mod.load_config.cache_clear()
    import src.backend.app as app_mod
    app_mod = importlib.reload(app_mod)
    with TestClient(app_mod.app) as client:
        yield client, tmp
    mp.undo()
    config_mod.load_config.cache_clear()


def test_health_and_metrics(api):
    client, _ = api
    h = client.get("/api/health").json()
    assert h["database"] is True and h["kubernetes"] is False and h["deception_enabled"] is False
    m = client.get("/api/metrics").json()
    for key in ("total_flows", "benign_flows", "malicious_flows", "active_threats", "active_decoys",
                "total_interactions", "model"):
        assert key in m


@requires_dataset
def test_detection_run_and_query(api):
    client, _ = api
    r = client.post("/api/detection/run", json={"file": "cve202143798_20230309T0401.pcap_Flow.csv"})
    assert r.status_code == 200, r.text
    assert r.json()["flows"] == 36 and r.json()["source"] == "dataset"
    rows = client.get("/api/detections", params={"source": "dataset", "limit": 100}).json()
    assert len(rows) == 36 and all(x["capture_file"] == "cve202143798_20230309T0401.pcap_Flow.csv" for x in rows)
    for x in client.get("/api/detections", params={"malicious": True}).json():
        assert x["is_malicious"] == 1
    assert len(client.get("/api/detections/latest", params={"limit": 5}).json()) == 5
    assert client.get("/api/detections/stats").json()["by_class"]


@pytest.mark.parametrize("name,code", [("../../etc/passwd.csv", 400), ("x/y.csv", 400), ("nope.csv", 404),
                                       ("notcsv.txt", 400)])
def test_detection_run_rejects_bad_files(api, name, code):
    client, _ = api
    assert client.post("/api/detection/run", json={"file": name}).status_code == code


def test_capture_process_validation_and_run(api):
    client, tmp = api
    assert client.post("/api/capture/process", json={"pcap": "../x.pcap"}).status_code == 400
    assert client.post("/api/capture/process", json={"pcap": "missing.pcap"}).status_code == 404
    shutil.copy(FIXTURES / "cni0-test.pcap", tmp / "pcap" / "win_api.pcap")
    st = client.get("/api/capture/status").json()
    assert st["pending"] == ["win_api.pcap"] and st["service"]["running"] is False
    res = client.post("/api/capture/process", json={"pcap": "win_api.pcap"}).json()["processed"][0]
    assert res["status"] in ("classified", "failed")  # failed only if CICFlowMeter is unavailable
    assert client.post("/api/capture/stop").json()["running"] is False


def test_simulated_event_flow(api):
    client, _ = api
    before = client.get("/api/metrics").json()["total_flows"]
    assert client.post("/api/deception/enable").json()["enabled"] is True
    r = client.post("/api/deception/test-event", json={"attack_class": "CVE-2019-20933", "confidence": 0.97,
                                                        "src_ip": "192.0.2.10", "note": "api test"})
    assert r.status_code == 200 and r.json()["simulated"] is True
    client.post("/api/deception/cycle")
    acts = client.get("/api/deception/actions").json()
    sim = [a for a in acts if a["simulated"] == 1]
    assert sim and sim[0]["decoy_profile"] == "influxdb" and sim[0]["reason"].startswith("SIMULATED")
    assert sim[0]["result"] == "failed"  # Kubernetes unavailable in this test
    assert client.get("/api/metrics").json()["total_flows"] == before  # simulated events are not detections
    assert client.post("/api/deception/disable").json()["enabled"] is False


def test_deception_input_validation(api):
    client, _ = api
    assert client.post("/api/deception/test-event", json={"attack_class": "Nope", "confidence": 0.9}).status_code == 400
    assert client.post("/api/deception/test-event", json={"attack_class": "CVE-2019-5736", "confidence": 2}).status_code == 422
    assert client.post("/api/deception/decoys", json={"profile": "nope"}).status_code == 400
    assert client.delete("/api/deception/decoys/not_a_decoy").status_code == 400
    assert client.delete("/api/deception/decoys/decoy-grafana").status_code == 503  # cluster unavailable
    assert client.post("/api/deception/decoys", json={"profile": "grafana"}).status_code == 503


def test_status_endpoints_without_cluster(api):
    client, _ = api
    assert client.get("/api/kubernetes/status").json()["connected"] is False
    s = client.get("/api/deception/status").json()
    assert s["kubernetes_available"] is False and "stage" in s
    pol = client.get("/api/deception/policy").json()
    assert pol["attack_policy"]["CVE-2021-25741"] == ["k8s-inventory"]
    perf = client.get("/api/model/performance").json()
    assert "test" in perf and "registry" in perf
    assert client.get("/api/classes").json()["0"] == "Benign"


def test_monitoring_overview_and_incremental_feed(api):
    client, tmp = api
    from src.utils import db
    from src.utils.config import load_config
    import pandas as pd

    with db.connect(db.db_path(load_config())) as c:
        cid = db.upsert_capture(c, "mon.pcap", status="classified", started_at="2026-10-31T10:00:00+00:00",
                                ended_at="2026-10-31T10:00:10+00:00", flows=2, packets=20, pipeline_s=1.0)
        db.insert_detections(c, pd.DataFrame([
            {"src_ip": "10.42.0.9", "dst_ip": "10.42.0.45", "dst_port": 1880, "predicted_label": 2,
             "predicted_class": "Node-RED Reconnaissance", "confidence": 0.9, "is_malicious": True, "source": "pcap",
             "detected_at": "2026-10-31T10:00:11+00:00", "status": "attack"},
            {"src_ip": "10.42.0.8", "dst_ip": "10.42.0.44", "dst_port": 3000, "predicted_label": 0,
             "predicted_class": "Benign", "confidence": 0.9, "is_malicious": False, "source": "pcap",
             "detected_at": "2026-10-31T10:00:11+00:00", "status": "benign"}]), capture_id=cid)
        db.insert_row(c, "behavior_alerts", capture_id=cid, src_ip="10.42.0.8", dst_port=3000, flows=30,
                      detected_at="2026-10-31T10:00:11+00:00")
    ov = client.get("/api/monitoring/overview", params={"windows": 5}).json()
    assert {"summary", "windows", "classes", "sources", "alerts", "capture", "pending", "simulations"} <= set(ov)
    w = next(x for x in ov["windows"] if x["id"] == cid)
    assert (w["benign"], w["malicious"], w["suspicious"], w["alerts"]) == (1, 1, 1, 1)
    feed = client.get("/api/monitoring/feed").json()
    by_src = {r["src_ip"]: r for r in feed}
    assert by_src["10.42.0.9"]["status"] == "attack" and by_src["10.42.0.8"]["behavioural"] == 1
    newest = max(r["id"] for r in feed)
    assert client.get("/api/monitoring/feed", params={"after_id": newest}).json() == []
    assert [r["src_ip"] for r in client.get("/api/monitoring/feed", params={"mechanism": "behavioural"}).json()] == ["10.42.0.8"]
    assert [r["src_ip"] for r in client.get("/api/monitoring/feed", params={"app": "nodered"}).json()] == ["10.42.0.9"]
    assert client.get("/api/monitoring/feed", params={"origin": "simulation"}).json() == []
    assert client.get("/api/monitoring/feed", params={"status": "exploited"}).status_code == 422


def test_simulator_endpoints_without_cluster(api):
    client, tmp = api
    sc = client.get("/api/simulations/scenarios").json()
    assert "sequential" in sc["categories"]["recon"] and sc["limits"]["max_requests"][1] <= 1000
    ok_req = {"category": "recon", "scenario": "sequential", "target": "nodered"}
    r = client.post("/api/simulations", json=ok_req)
    assert r.status_code == 503 and "Kubernetes unavailable" in r.json()["detail"]     # no cluster: nothing started
    assert client.get("/api/simulations").json() == []
    assert client.post("/api/simulations", json={**ok_req, "scenario": "exploit"}).status_code == 422
    assert client.post("/api/simulations", json={**ok_req, "target": "10.0.0.1"}).status_code == 422
    assert client.post("/api/simulations", json={**ok_req, "max_requests": 999999}).status_code == 422
    assert client.post("/api/simulations", json={**ok_req, "category": "rce"}).status_code == 422
    assert client.get("/api/simulations/sim-x").status_code == 404
    assert client.get("/api/simulations/sim-x/logs").status_code == 404
    assert client.get("/api/simulations/sim-x/cleanup").status_code == 404
    assert client.post("/api/simulations/sim-x/cancel").status_code == 404
    rec = client.post("/api/simulations/recover").json()
    assert rec["interrupted"] == [] and rec["errors"]                                   # reports, does not crash
