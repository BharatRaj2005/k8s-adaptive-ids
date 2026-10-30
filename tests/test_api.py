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
