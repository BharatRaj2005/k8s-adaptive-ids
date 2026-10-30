import copy
import fcntl
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pandas as pd
import pytest

from src.capture import service
from src.capture.process_pcap import pending_pcaps, process_pcap, resolve_pcap
from src.capture.tcpdump import CaptureError, _parse_counts, build_command, capture_window, choose_next_window
from src.detection.predictor import FlowPredictor
from src.feature_extraction.cicflowmeter import LINKTYPE_ETHERNET, convert_pcap, java_command, pcap_linktype
from src.preprocessing.lab_data import label_flows
from src.preprocessing.schema import DST_IP, DST_PORT, SRC_IP, SRC_PORT
from src.utils import db
from tests.conftest import FIXTURES

WCFG = {"default_seconds": 10, "min_seconds": 5, "max_seconds": 30, "high_rate_pps": 200, "low_rate_pps": 20}


def _cicflowmeter_available(cfg) -> bool:
    try:
        java_command(cfg, Path("/tmp"), Path("/tmp"))
        return shutil.which(cfg["cicflowmeter"]["java"]) is not None
    except Exception:
        return False


def _tcpdump_can_capture() -> bool:
    try:
        out = subprocess.run(["getcap", "/usr/bin/tcpdump"], capture_output=True, text=True).stdout
        return "cap_net_raw" in out
    except FileNotFoundError:
        return False


@pytest.fixture
def pipeline_cfg(cfg, tmp_path, trained_model_dir):
    c = copy.deepcopy(cfg)
    c["paths"]["pcap_dir"] = str(tmp_path / "pcap")
    c["paths"]["flows_dir"] = str(tmp_path / "flows")
    c["paths"]["models_dir"] = str(trained_model_dir.parent)
    c["detection"]["active_model"] = trained_model_dir.name
    c["database"]["path"] = str(tmp_path / "ids.sqlite")
    c["capture"]["pid_file"] = str(tmp_path / "capture.pid")
    c["capture"]["state_file"] = str(tmp_path / "state.json")
    c["capture"]["interface"] = "lo"
    c["capture"]["window"] = {**WCFG, "default_seconds": 1.5}
    return c


def _write_pcap_header(path: Path, linktype: int) -> Path:
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    return path


def _make_traffic(stop: threading.Event):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    srv.settimeout(0.2)
    while not stop.is_set():
        c = socket.create_connection(("127.0.0.1", port))
        try:
            s, _ = srv.accept()
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            s.recv(100)
            s.close()
        except socket.timeout:
            pass
        c.close()
        time.sleep(0.05)
    srv.close()


# --- tcpdump command and window logic -------------------------------------------------

def test_build_command_uses_argument_list(tmp_path):
    cmd = build_command("/usr/bin/tcpdump", "lo", tmp_path / "x.pcap.part", 0, "tcp port 80")
    assert cmd == ["/usr/bin/tcpdump", "-i", "lo", "-nn", "-s", "0", "-U", "-w", str(tmp_path / "x.pcap.part"),
                   "tcp port 80"]


@pytest.mark.parametrize("iface", ["cni0; rm -rf /", "", "x" * 20, "does-not-exist0"])
def test_invalid_interfaces_rejected(iface, tmp_path):
    with pytest.raises(CaptureError):
        build_command("/usr/bin/tcpdump", iface, tmp_path / "x.pcap")


def test_adaptive_window_selection():
    assert choose_next_window(5000, 10, WCFG) == 5    # 500 pps -> shortest
    assert choose_next_window(500, 10, WCFG) == 10    # 50 pps -> default
    assert choose_next_window(100, 10, WCFG) == 30    # 10 pps -> longest
    assert choose_next_window(0, 10, WCFG) == 30
    assert choose_next_window(None, 10, WCFG) == 10   # unknown count -> default


def test_parse_tcpdump_counts():
    assert _parse_counts("12 packets captured\n15 packets received by filter\n0 packets dropped by kernel\n") == (12, 0)
    assert _parse_counts("garbage") == (None, None)


# --- PCAP -> CSV ----------------------------------------------------------------------

def test_linktype_detection(tmp_path):
    assert pcap_linktype(FIXTURES / "cni0-test.pcap") == LINKTYPE_ETHERNET
    assert pcap_linktype(_write_pcap_header(tmp_path / "sll.pcap", 276)) == 276


def test_unsupported_inputs_fail_cleanly(tmp_path, cfg):
    sll = _write_pcap_header(tmp_path / "sll.pcap", 276)
    res = convert_pcap(sll, tmp_path / "out", cfg)
    assert res.status == "failed" and "SLL2" in res.error and res.csv is None
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a pcap at all, definitely")
    assert convert_pcap(junk, tmp_path / "out", cfg).status == "failed"
    ng = tmp_path / "ng.pcap"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 28)
    assert "pcapng" in convert_pcap(ng, tmp_path / "out", cfg).error
    assert convert_pcap(tmp_path / "missing.pcap", tmp_path / "out", cfg).status == "failed"


def test_pcap_to_csv_conversion(tmp_path, cfg):
    if not _cicflowmeter_available(cfg):
        pytest.skip("CICFlowMeter not available")
    res = convert_pcap(FIXTURES / "cni0-test.pcap", tmp_path / "out", cfg)
    assert res.status == "converted", res.error
    assert res.flows == 2
    assert Path(res.csv).name == "cni0-test.pcap_Flow.csv" and Path(res.csv).is_file()
    assert not list((tmp_path / "out").glob("cfm-*"))  # staging directory removed


# --- processing and storage -----------------------------------------------------------

def test_resolve_pcap_restricts_paths(pipeline_cfg, tmp_path):
    pcap_dir = Path(pipeline_cfg["paths"]["pcap_dir"])
    pcap_dir.mkdir(parents=True)
    ok = pcap_dir / "a.pcap"
    shutil.copy(FIXTURES / "cni0-test.pcap", ok)
    assert resolve_pcap(ok, pipeline_cfg) == ok.resolve()
    with pytest.raises(ValueError):
        resolve_pcap(FIXTURES / "cni0-test.pcap", pipeline_cfg)  # outside capture dir
    with pytest.raises(ValueError):
        resolve_pcap(pcap_dir / ".." / "a.pcap", pipeline_cfg)
    (pcap_dir / "b.txt").write_text("x")
    with pytest.raises(ValueError):
        resolve_pcap(pcap_dir / "b.txt", pipeline_cfg)


def test_process_pcap_stores_detections(pipeline_cfg, trained_model_dir):
    if not _cicflowmeter_available(pipeline_cfg):
        pytest.skip("CICFlowMeter not available")
    pcap_dir = Path(pipeline_cfg["paths"]["pcap_dir"])
    pcap_dir.mkdir(parents=True)
    pcap = pcap_dir / "win_test.pcap"
    shutil.copy(FIXTURES / "cni0-test.pcap", pcap)
    assert pending_pcaps(pipeline_cfg) == [pcap]
    res = process_pcap(pcap, FlowPredictor(trained_model_dir), pipeline_cfg)
    assert res["status"] == "classified" and res["detections"] == 2
    with db.connect(db.db_path(pipeline_cfg)) as conn:
        cap = conn.execute("SELECT * FROM captures").fetchone()
        dets = db.query_df(conn, "SELECT * FROM detections")
    assert cap["status"] == "classified" and cap["flows"] == 2 and cap["csv_file"] == "win_test.pcap_Flow.csv"
    assert (dets["source"] == "pcap").all() and (dets["simulated"] == 0).all()
    assert (dets["capture_id"] == cap["id"]).all()
    assert set(dets["dst_ip"]) == {"10.42.0.107", "10.42.0.112"}
    assert dets["true_label"].isna().all()
    assert pending_pcaps(pipeline_cfg) == []


def test_db_stores_nulls_for_missing_fields(tmp_path):
    pred = pd.DataFrame([{c: None for c in db.DETECTION_COLUMNS}])
    pred = pred.assign(predicted_label=0, predicted_class="Benign", confidence=0.9, is_malicious=False,
                       source="dataset", detected_at="2026-01-01T00:00:00Z", src_port=pd.NA)
    with db.connect(tmp_path / "x.sqlite") as conn:
        assert db.insert_detections(conn, pred) == 1
        row = conn.execute("SELECT * FROM detections").fetchone()
    assert row["src_ip"] is None and row["src_port"] is None and row["is_malicious"] == 0


# --- live capture (needs tcpdump capabilities) ----------------------------------------

@pytest.mark.skipif(not _tcpdump_can_capture(), reason="tcpdump lacks capture capabilities")
def test_capture_window_on_loopback(pipeline_cfg, tmp_path):
    stop = threading.Event()
    t = threading.Thread(target=_make_traffic, args=(stop,))
    t.start()
    try:
        res = capture_window(1.5, pipeline_cfg, out_dir=tmp_path / "pcap")
    finally:
        stop.set()
        t.join()
    assert res.error is None
    assert Path(res.pcap).is_file() and res.pcap.endswith(".pcap")
    assert res.packets and res.packets > 0
    assert not list((tmp_path / "pcap").glob("*.part"))


@pytest.mark.skipif(not _tcpdump_can_capture(), reason="tcpdump lacks capture capabilities")
def test_service_prevents_overlapping_captures(pipeline_cfg, tmp_path):
    lock_path = tmp_path / service.LOCK_NAME
    with open(lock_path, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(service.ServiceError, match="already running"):
            service.run(windows=1, process=False, cfg=pipeline_cfg)


@pytest.mark.skipif(not _tcpdump_can_capture(), reason="tcpdump lacks capture capabilities")
def test_service_end_to_end_on_loopback(pipeline_cfg):
    if not _cicflowmeter_available(pipeline_cfg):
        pytest.skip("CICFlowMeter not available")
    stop = threading.Event()
    t = threading.Thread(target=_make_traffic, args=(stop,))
    t.start()
    try:
        stats = service.run(windows=2, process=True, cfg=pipeline_cfg)
    finally:
        stop.set()
        t.join()
    assert stats["windows"] == 2 and stats["processed"] == 2 and stats["failed"] == 0
    with db.connect(db.db_path(pipeline_cfg)) as conn:
        caps = db.query_df(conn, "SELECT * FROM captures")
        n_det = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    assert len(caps) == 2 and set(caps["status"]) <= {"classified", "empty"}
    assert n_det == caps["flows"].sum() > 0
    assert caps["next_window_s"].notna().all()
    state = service.read_state(pipeline_cfg)
    assert state["status"] == "stopped" and not state["running"]


# --- lab ground truth -----------------------------------------------------------------

def test_lab_attack_labelling():
    df = pd.DataFrame({SRC_IP: ["10.0.0.9", "10.0.0.5", "10.0.0.9", "10.0.0.1"],
                       DST_IP: ["10.0.0.5", "10.0.0.9", "10.0.0.53", "10.0.0.5"],
                       SRC_PORT: [40000, 1880, 40001, 40002], DST_PORT: [1880, 40003, 53, 1880]})
    manifest = {"kind": "attack", "attacker_ips": ["10.0.0.9"], "target_port": 1880, "attack_label": 2}
    labels = label_flows(df, manifest, 0)
    assert labels.tolist()[:2] == [2, 2]       # attacker <-> target port, either direction
    assert pd.isna(labels.iloc[2])             # attacker DNS lookup: ambiguous
    assert labels.iloc[3] == 0                 # unrelated flow
