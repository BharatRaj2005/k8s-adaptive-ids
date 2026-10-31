"""Dataset generation: plan limits, generator, ground-truth labelling, splitting and balancing."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.datagen import build as B
from src.datagen.kube import job_manifest, job_name
from src.datagen.labeling import LABEL, STATUS, label_session
from src.datagen.plan import PlanError, Session, build_plan, load_datagen_config, validate_session
from src.datagen.session import parse_generator_log

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "kubernetes/traffic-generator/datagen_generator.py"
GENERATED = ROOT / "data/generated"


@pytest.fixture(scope="module")
def dcfg():
    return copy.deepcopy(load_datagen_config())


# --- plan and limits ---------------------------------------------------------------------------
def test_plan_roles_keep_sessions_whole(dcfg):
    plan = build_plan(dcfg)
    assert len({s.session_id for s in plan}) == len(plan)
    held = dcfg["split"]["held_out_scanner"]
    assert {s.role for s in plan if s.profile == held} == {"heldout_scanner"}
    for scanner in {s.profile for s in plan if s.category == "recon"} - {held}:
        roles = [s.role for s in plan if s.profile == scanner]
        assert roles.count("test") == 1 and roles.count("val") == 1 and roles.count("train") >= 2
    for prof in {s.profile for s in plan if s.category == "benign"}:
        assert "test" in [s.role for s in plan if s.profile == prof]
    assert len({s.seed for s in plan}) == len(plan)


def test_plan_covers_every_scanner_and_app(dcfg):
    plan = build_plan(dcfg)
    assert {s.profile for s in plan if s.category == "recon"} == set(dcfg["tiers"]["recon"])
    for scanner in dcfg["tiers"]["recon"]:
        apps = {a for s in plan if s.profile == scanner for a in s.apps}
        assert len(apps) >= 2, scanner


@pytest.mark.parametrize("change, msg", [
    ({"delay": [0.001, 0.01]}, "floor"),
    ({"requests": 5000}, "requests"),
    ({"workers": 50}, "workers"),
])
def test_limits_reject_sessions(dcfg, change, msg):
    s = Session("x", "recon", "seq_wordlist", "high", 1, 0, ["nodered"], 1, {"delay": [0.1, 0.1], "requests": 10, **change}, 2)
    with pytest.raises(PlanError, match=msg):
        validate_session(s, dcfg)


def test_limits_reject_unknown_application(dcfg):
    s = Session("x", "recon", "seq_wordlist", "high", 1, 0, ["kube-apiserver"], 1, {"delay": [0.1, 0.1], "requests": 10}, 2)
    with pytest.raises(PlanError, match="allow-list"):
        validate_session(s, dcfg)


def test_job_manifest_is_hardened_and_namespaced(dcfg):
    s = build_plan(dcfg)[0]
    job = job_manifest(s, dcfg)
    assert job["metadata"]["namespace"] == "ids-traffic"
    assert job["metadata"]["name"] == job_name(s.session_id) and len(job["metadata"]["name"]) <= 63
    pod = job["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert pod["automountServiceAccountToken"] is False and pod["securityContext"]["runAsNonRoot"] is True
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"] and c["securityContext"]["readOnlyRootFilesystem"]
    assert job["spec"]["activeDeadlineSeconds"] <= dcfg["limits"]["max_session_seconds"] + 60
    env = {e["name"]: e["value"] for e in c["env"]}
    assert env["PROFILE"] == s.profile and env["SESSION_ID"] == s.session_id
    assert all(".target-apps.svc.cluster.local" in u for u in env["APP_URLS"].split(","))


# --- generator (the real script, against local HTTP/1.1 servers) ------------------------------
class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, body=True):
        data = b"x" * 64
        self.send_response(200 if self.path in ("/", "/login", "/api/health", "/health") else 404)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body:
            self.wfile.write(data)

    do_GET = do_OPTIONS = _reply

    def do_HEAD(self):
        self._reply(False)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def local_apps():
    servers = [ThreadingHTTPServer(("127.0.0.1", 0), _H) for _ in range(3)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield ",".join(f"{a}=http://127.0.0.1:{s.server_address[1]}" for a, s in zip(("nodered", "grafana", "influxdb"), servers))
    for s in servers:
        s.shutdown()


def _run_generator(env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(GENERATOR)], env={**os.environ, **env}, capture_output=True,
                          text=True, timeout=60)


PROFILES = ["browse", "poller", "keepalive_client", "burst_refresh", "asset_loader", "api_consumer",
            "seq_wordlist", "shuffled_jitter", "keepalive_scanner", "threaded_parallel", "head_crawler", "multi_app_sweep"]


@pytest.mark.parametrize("profile", PROFILES)
def test_generator_profiles_log_every_connection(local_apps, profile):
    proc = _run_generator({"PROFILE": profile, "APP_URLS": local_apps, "TARGET_APPS": "nodered,grafana,influxdb",
                           "REQUESTS": "24", "DELAY_MIN": "0.02", "DELAY_MAX": "0.03", "WORKERS": "3",
                           "RECONNECT_MIN": "3", "RECONNECT_MAX": "5", "MAX_SECONDS": "30", "SEED": "7"})
    assert proc.returncode == 0, proc.stderr
    g = parse_generator_log(proc.stdout)
    assert g["completed"] and 0 < g["requests"] <= 24 and g["request_errors"] == 0
    events = [json.loads(x) for x in proc.stdout.splitlines()]
    opened = {e["cid"]: e for e in events if e["ev"] == "conn_open"}
    assert all(e["cid"] in opened for e in events if e["ev"] == "req")
    assert all(isinstance(c["lport"], int) and c["lport"] > 0 for c in g["connections"])
    if profile in ("keepalive_client", "keepalive_scanner"):
        assert len(g["connections"]) < g["requests"]          # several requests per connection
    if profile == "head_crawler":
        assert set(g["method_counts"]) == {"HEAD"}


def test_generator_scanners_differ(local_apps):
    seen = {}
    for p in ("seq_wordlist", "shuffled_jitter", "keepalive_scanner", "head_crawler", "multi_app_sweep"):
        out = _run_generator({"PROFILE": p, "APP_URLS": local_apps, "TARGET_APPS": "nodered,grafana,influxdb",
                              "REQUESTS": "30", "DELAY_MIN": "0.02", "DELAY_MAX": "0.02", "SEED": "3",
                              "RECONNECT_MIN": "5", "RECONNECT_MAX": "8"}).stdout
        reqs = [json.loads(x) for x in out.splitlines() if '"ev": "req"' in x]
        seen[p] = (tuple(r["path"] for r in reqs), tuple(sorted({r["method"] for r in reqs})),
                   len({r["cid"] for r in reqs}))
    assert len({v[0] for v in seen.values()}) == len(seen)        # different endpoint orders
    assert len({(v[1], v[2]) for v in seen.values()}) >= 3        # different methods / connection behaviour


@pytest.mark.parametrize("env, msg", [
    ({"TARGET_APPS": "kubernetes"}, "TARGET_APPS"),
    ({"REQUESTS": "5000"}, "REQUESTS"),
    ({"DELAY_MIN": "0.001"}, "delay"),
    ({"WORKERS": "64"}, "WORKERS"),
    ({"PROFILE": "exploit"}, "PROFILE"),
])
def test_generator_enforces_its_own_limits(local_apps, env, msg):
    base = {"PROFILE": "seq_wordlist", "APP_URLS": local_apps, "TARGET_APPS": "nodered", "REQUESTS": "5",
            "DELAY_MIN": "0.05"}
    proc = _run_generator({**base, **env})
    assert proc.returncode != 0 and msg in proc.stderr


# --- labelling ---------------------------------------------------------------------------------
GEN, NODERED, GRAFANA, BG, CORE_DNS, OTHER = "10.42.0.50", "10.42.0.21", "10.42.0.24", "10.42.0.36", "10.42.0.2", "10.42.0.9"


def _meta(label=2, apps=("nodered",)):
    return {"session_id": "s1", "category": "recon" if label else "benign", "profile": "seq_wordlist", "tier": "high",
            "role": "train", "label": label, "apps": list(apps), "pod": {"ip": GEN},
            "benign_generator_ips": [BG],
            "targets": {"nodered": {"port": 1880, "cluster_ip": "10.43.0.71", "pod_ips": [NODERED]},
                        "grafana": {"port": 3000, "cluster_ip": "10.43.0.63", "pod_ips": [GRAFANA]}},
            "generator": {"first_ts": "2026-10-31T07:00:00+00:00", "last_ts": "2026-10-31T07:01:00+00:00"},
            "capture": {"started_at": "2026-10-31T06:59:50+00:00", "ended_at": "2026-10-31T07:01:10+00:00"}}


CONNS = [
    {"cid": 1, "app": "nodered", "lport": 40001, "open": "2026-10-31T07:00:00+00:00", "close": "2026-10-31T07:00:01+00:00"},
    {"cid": 2, "app": "nodered", "lport": 40002, "open": "2026-10-31T07:00:10+00:00", "close": "2026-10-31T07:00:11+00:00"},
    # local port 40002 reused later in the session by another connection
    {"cid": 3, "app": "nodered", "lport": 40002, "open": "2026-10-31T07:00:40+00:00", "close": "2026-10-31T07:00:41+00:00"},
    {"cid": 4, "app": "nodered", "lport": 40004, "open": "2026-10-31T07:00:58+00:00", "close": "2026-10-31T07:01:00+00:00"},
]


def _flow(src, sport, dst, dport, ts, dur_us=1000, proto=6, extra=0):
    return {"Flow ID": f"{src}-{dst}-{sport}-{dport}-{proto}", "Src IP": src, "Src Port": sport, "Dst IP": dst,
            "Dst Port": dport, "Protocol": proto, "Timestamp": ts, "Flow Duration": dur_us,
            "Total Fwd Packet": 5 + extra, "Total Bwd packets": 4}


def _label(rows, meta=None, conns=CONNS):
    return label_session(pd.DataFrame(rows), meta or _meta(), conns, {"slack_before_s": 1, "slack_after_s": 2,
                         "capture_edge_s": 0.5}, features=["Total Fwd Packet", "Total Bwd packets"])


def test_matched_session_flow_gets_session_label():
    out = _label([_flow(GEN, 40001, NODERED, 1880, "2026-10-31 07:00:00.100")])
    assert out[STATUS][0] == "session_traffic" and out[LABEL][0] == 2 and out["_conn_id"][0] == 1


def test_reversed_direction_is_matched():
    out = _label([_flow(NODERED, 1880, GEN, 40001, "2026-10-31 07:00:00.100")])
    assert out[STATUS][0] == "session_traffic"


def test_reused_local_port_is_resolved_by_time():
    out = _label([_flow(GEN, 40002, NODERED, 1880, "2026-10-31 07:00:10.200"),
                  _flow(GEN, 40002, NODERED, 1880, "2026-10-31 07:00:40.200", extra=1)])
    assert list(out["_conn_id"]) == [2, 3] and set(out[STATUS]) == {"session_traffic"}


def test_ip_alone_never_labels_a_flow():
    out = _label([_flow(GEN, 49999, NODERED, 1880, "2026-10-31 07:00:20"),          # port not logged
                  _flow(GEN, 40001, NODERED, 1880, "2026-10-31 07:00:30"),          # logged port, wrong time
                  _flow(GEN, 40001, GRAFANA, 3000, "2026-10-31 07:00:00.500")])     # app not targeted
    assert set(out[STATUS]) == {"generator_unmatched"} and out[LABEL].isna().all()


def test_dns_and_background_are_never_attack():
    out = _label([_flow(GEN, 51000, CORE_DNS, 53, "2026-10-31 07:00:00.050", proto=17),
                  _flow(OTHER, 33000, NODERED, 1880, "2026-10-31 07:00:05"),
                  _flow(BG, 33001, GRAFANA, 3000, "2026-10-31 07:00:06")])
    assert list(out[STATUS]) == ["generator_dns", "background_cluster", "background_generator"]
    assert out[LABEL].isna()[0] and list(out[LABEL][1:]) == [0, 0]


def test_flow_crossing_session_boundary_is_ambiguous():
    out = _label([_flow(GEN, 40004, NODERED, 1880, "2026-10-31 07:00:59", dur_us=5_000_000)])
    assert out[STATUS][0] == "crosses_boundary" and out[LABEL].isna()[0]


def test_invalid_and_duplicate_rows_are_discarded():
    f = _flow(GEN, 40001, NODERED, 1880, "2026-10-31 07:00:00.100")
    out = _label([f, dict(f), _flow(OTHER, 1, NODERED, 1880, "2026-10-31 07:00:05", dur_us=-5)])
    assert list(out[STATUS]) == ["session_traffic", "duplicate", "invalid"]


def test_benign_session_label():
    out = _label([_flow(GEN, 40001, NODERED, 1880, "2026-10-31 07:00:00.100")], meta=_meta(label=0))
    assert out[LABEL][0] == 0 and out[STATUS][0] == "session_traffic"


# --- balancing ---------------------------------------------------------------------------------
def test_fill_quota_spreads_evenly():
    assert B.fill_quota({"a": 10, "b": 1000, "c": 1000}, 610) == {"a": 10, "b": 300, "c": 300}
    assert B.fill_quota({"a": 5, "b": 7}, 100) == {"a": 5, "b": 7}
    assert sum(B.fill_quota({"a": 333, "b": 444, "c": 555}, 1000).values()) == 1000


def _pool():
    rng = np.random.default_rng(0)
    rows = []
    for s, n in (("r1", 900), ("r2", 50), ("r3", 900)):
        rows += [{"_session": s, "Label": 2, "_status": "session_traffic", "f": rng.random()} for _ in range(n)]
    for s, n in (("b1", 400), ("b2", 300)):
        rows += [{"_session": s, "Label": 0, "_status": "session_traffic", "f": rng.random()} for _ in range(n)]
    rows += [{"_session": "b1", "Label": 0, "_status": "background_cluster", "f": rng.random()} for _ in range(5000)]
    return pd.DataFrame(rows)


def test_balance_never_duplicates_and_records_shortfall():
    pool = _pool()
    bal, rep = B.balance(pool, {"target_per_class": 1500, "max_background_share": 0.3, "random_state": 1})
    assert bal.index.is_unique and set(bal.index) <= set(pool.index)
    assert rep[2]["selected"] == 1500 and rep[2]["sessions"] == 3
    assert (bal[bal.Label == 2]._session == "r2").sum() == 50          # small session kept whole
    assert rep[0]["session_traffic"] == 700 and rep[0]["background"] == 450
    assert rep[0]["shortfall"] == 350                                  # not padded with background or copies


# --- the generated dataset itself (skipped until it has been built) ---------------------------
built = pytest.mark.skipif(not (GENERATED / "manifest.json").is_file(), reason="generated dataset not built")


@built
def test_generated_splits_are_disjoint_by_session():
    sets = {n: pd.read_csv(GENERATED / f"labelled/{n}.csv.gz", usecols=["_session", "_status", "Label"])
            for n in B.SETS}
    sessions = {n: set(d._session) for n, d in sets.items()}
    names = list(sessions)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            assert not sessions[a] & sessions[b], (a, b)
    for d in sets.values():
        assert d.Label.notna().all()
        assert not d._status.isin(["generator_dns", "generator_unmatched", "crosses_boundary", "invalid",
                                   "duplicate"]).any()


@built
def test_balanced_set_is_subset_of_training_sessions():
    bal = pd.read_csv(GENERATED / "labelled/train_balanced.csv.gz", usecols=["_session", "Flow ID", "Timestamp", "Label"])
    train = pd.read_csv(GENERATED / "labelled/train_natural.csv.gz", usecols=["_session", "Flow ID", "Timestamp", "Label"])
    assert not bal.duplicated().any()
    assert set(map(tuple, bal.values)) <= set(map(tuple, train.values))


@built
def test_generated_flows_match_model_feature_schema():
    from src.datagen.session import model_features
    from src.utils.config import load_config

    feats = model_features(load_config())
    cols = pd.read_csv(GENERATED / "labelled/test_natural.csv.gz", nrows=1).columns
    assert feats and not [f for f in feats if f not in cols]
