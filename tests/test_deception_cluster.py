"""Integration test against the real K3s cluster (skipped when it is not reachable).

Deploys a real decoy in ids-deception through the least-privilege identity, sends
a request to it from the traffic-generator pod, checks that the controller stores
the interaction with the right source IP, and removes the decoy again.
"""
import copy
import os
import subprocess
import time

import pytest

from src.deception.controller import MapeKController
from src.utils import db
from src.utils.config import project_path

ADMIN = {**os.environ, "KUBECONFIG": os.path.expanduser("~/.kube/config")}


def _kubectl(*args, check=True):
    return subprocess.run(["kubectl", *args], env=ADMIN, capture_output=True, text=True, check=check).stdout.strip()


def _cluster_ready(cfg) -> bool:
    if not project_path(cfg["deception"]["kubeconfig"]).is_file():
        return False
    try:
        return bool(_kubectl("-n", "ids-traffic", "get", "pod", "-l", "mode=benign", "-o", "name"))
    except Exception:
        return False


@pytest.fixture
def live_ctl(cfg, tmp_path):
    if not _cluster_ready(cfg):
        pytest.skip("cluster / ids-controller kubeconfig / traffic generator not available")
    c = copy.deepcopy(cfg)
    c["database"]["path"] = str(tmp_path / "ids.sqlite")
    ctl = MapeKController(c)
    if ctl.manager is None:
        pytest.skip(f"Kubernetes unavailable: {ctl.manager_error}")
    if "decoy-http-recon" in ctl.manager.list_decoys():
        pytest.skip("decoy-http-recon already running in the cluster")
    yield ctl, c
    ctl.manager.remove("decoy-http-recon")


def test_real_decoy_lifecycle(live_ctl):
    ctl, cfg = live_ctl
    res = ctl.manual_deploy("http-recon")
    assert res["result"] == "ok", res
    deadline = time.time() + 120
    while time.time() < deadline:
        ctl.run_cycle()
        with db.connect(db.db_path(cfg)) as c:
            row = c.execute("SELECT * FROM decoys WHERE name = 'decoy-http-recon' ORDER BY id DESC").fetchone()
        if row["status"] == "active":
            break
        time.sleep(2)
    assert row["status"] == "active", "decoy did not become ready"
    assert row["deploy_seconds"] > 0

    pod = _kubectl("-n", "ids-traffic", "get", "pod", "-l", "mode=benign", "-o", "jsonpath={.items[0].metadata.name}")
    pod_ip = _kubectl("-n", "ids-traffic", "get", "pod", pod, "-o", "jsonpath={.status.podIP}")
    out = _kubectl("-n", "ids-traffic", "exec", pod, "--", "python", "-c",
                   "import urllib.request as u; print(u.urlopen('http://decoy-http-recon.ids-deception.svc.cluster.local/api/status', timeout=5).status)")
    assert out == "200"

    for _ in range(10):
        ctl.run_cycle()
        with db.connect(db.db_path(cfg)) as c:
            ints = db.query_df(c, "SELECT * FROM interactions WHERE path = '/api/status'")
        if len(ints):
            break
        time.sleep(1)
    assert len(ints) == 1
    assert ints["src_ip"][0] == pod_ip and ints["decoy_name"][0] == "decoy-http-recon"
    assert ints["interaction_type"][0] == "page_request"

    # decoys cannot open outbound connections (NetworkPolicy egress: [])
    dpod = _kubectl("-n", "ids-deception", "get", "pod", "-l", "ids/decoy=decoy-http-recon",
                    "-o", "jsonpath={.items[0].metadata.name}")
    egress = subprocess.run(["kubectl", "-n", "ids-deception", "exec", dpod, "--", "python", "-c",
                             "import socket; socket.create_connection(('10.43.0.10', 53), timeout=3)"],
                            env=ADMIN, capture_output=True, text=True)
    assert egress.returncode != 0

    assert ctl.manual_remove("decoy-http-recon")["result"] == "ok"
    assert "decoy-http-recon" not in ctl.manager.list_decoys()
    with db.connect(db.db_path(cfg)) as c:
        assert c.execute("SELECT status FROM decoys ORDER BY id DESC").fetchone()[0] == "removed"
