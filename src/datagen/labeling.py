"""Ground-truth labels for the flows of one generation session.

A flow gets the session's label (benign 0 / reconnaissance 2) only when all of these hold:
  * one endpoint is the session's generator pod IP;
  * the other endpoint is a pod (or the ClusterIP) of an application the session targeted,
    on that application's service port;
  * the generator-side port is the local port of a connection in the generator's own log,
    and the flow lies inside that connection's lifetime (ports can be reused within a session);
  * the flow starts and ends within the session's time window (plus slack).

Everything else is decided separately:
  generator_dns         the generator's DNS lookups              -> ambiguous (excluded)
  generator_unmatched   other generator-pod flows, or no / several matching connections -> ambiguous
  crosses_boundary      a matched flow extending past the session window -> ambiguous
  other_generator_pod   flows of another datagen pod             -> ambiguous
  background_generator  the always-on benign generator pod       -> benign (verified: lab benign generator)
  background_cluster    cluster traffic not involving any generator pod -> benign (no attack source was
                        active: sessions run one at a time)
  invalid / duplicate   unparseable or negative-duration rows, exact repeated rows -> discarded

Labels are never inferred from an IP address alone.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, SRC_IP, SRC_PORT, TIMESTAMP, parse_timestamps, \
    read_flow_csv

SESSION, STATUS, REASON, APP, CATEGORY, PROFILE, TIER, ROLE = (
    "_session", "_status", "_reason", "_app", "_category", "_profile", "_tier", "_role")
TS, END_TS, CONN, EDGE = "_ts", "_end_ts", "_conn_id", "_edge"
SESSION_TRAFFIC = "session_traffic"
AMBIGUOUS = {"generator_dns", "generator_unmatched", "crosses_boundary", "other_generator_pod"}
BACKGROUND = {"background_generator", "background_cluster"}
DISCARDED = {"invalid", "duplicate"}
GROUND_TRUTH = {
    SESSION_TRAFFIC: "generator connection log (pod IP + local port + target endpoint + time window)",
    "background_generator": "always-on lab benign generator pod",
    "background_cluster": "cluster background during a session with no other traffic source active",
}


def _utc(series: pd.Series) -> pd.Series:
    ts = pd.to_datetime(series, utc=True, format="mixed", errors="coerce")
    return ts


def label_session(flows: pd.DataFrame, meta: dict[str, Any], connections: list[dict[str, Any]],
                  lcfg: dict[str, Any], pod_map: dict[str, str] | None = None,
                  features: list[str] | None = None) -> pd.DataFrame:
    """Return `flows` with label, status and bookkeeping columns (nothing is dropped)."""
    df = flows.copy().reset_index(drop=True)
    n = len(df)
    df[TS] = _utc(parse_timestamps(df[TIMESTAMP]))
    dur = pd.to_numeric(df.get("Flow Duration"), errors="coerce")
    df[END_TS] = df[TS] + pd.to_timedelta(dur.clip(lower=0).fillna(0), unit="us")
    for col, val in ((SESSION, meta["session_id"]), (CATEGORY, meta["category"]), (PROFILE, meta["profile"]),
                     (TIER, meta["tier"]), (ROLE, meta.get("role", ""))):
        df[col] = val
    status = np.full(n, "background_cluster", dtype=object)
    reason = np.full(n, "", dtype=object)
    conn_id = pd.array([pd.NA] * n, dtype="Int64")

    src, dst = df[SRC_IP].astype(str), df[DST_IP].astype(str)
    sport = pd.to_numeric(df[SRC_PORT], errors="coerce")
    dport = pd.to_numeric(df[DST_PORT], errors="coerce")

    # application of each flow (either direction), from the session's endpoint snapshot
    app = np.full(n, "", dtype=object)
    for name, t in meta["targets"].items():
        ips = set(t["pod_ips"]) | ({t["cluster_ip"]} if t.get("cluster_ip") else set())
        hit = (dst.isin(ips) & (dport == t["port"])) | (src.isin(ips) & (sport == t["port"]))
        app[hit.to_numpy()] = name
    df[APP] = app

    # other datagen pods (should not exist while a session runs; checked anyway)
    gen_ip = meta["pod"]["ip"]
    others = {ip for ip, pod in (pod_map or {}).items()
              if pod.startswith(f"{meta.get('namespace', 'ids-traffic')}/datagen-") and ip != gen_ip}
    status[(src.isin(others) | dst.isin(others)).to_numpy()] = "other_generator_pod"
    benign_gen = set(meta.get("benign_generator_ips") or [])
    status[((src.isin(benign_gen) | dst.isin(benign_gen)) & ~(src.isin(others) | dst.isin(others))).to_numpy()] = \
        "background_generator"

    is_src = (src == gen_ip).to_numpy()
    is_gen = is_src | (dst == gen_ip).to_numpy()
    my_port = np.where(is_src, sport, dport)
    peer_port = np.where(is_src, dport, sport)
    status[is_gen] = "generator_unmatched"
    reason[is_gen] = "no logged connection"
    status[is_gen & (peer_port == 53)] = "generator_dns"
    reason[is_gen & (peer_port == 53)] = "DNS lookup of the generator (no independent ground truth)"

    sb, sa = pd.Timedelta(seconds=lcfg["slack_before_s"]), pd.Timedelta(seconds=lcfg["slack_after_s"])
    g = meta["generator"]
    w0, w1 = pd.Timestamp(g["first_ts"]) - sb, pd.Timestamp(g["last_ts"]) + sa
    conns = pd.DataFrame(connections)
    if len(conns):
        conns["open"] = _utc(conns["open"])
        conns["close"] = _utc(conns["close"]).fillna(pd.Timestamp(g["last_ts"]))
    targeted = set(meta["apps"])
    cand = np.flatnonzero(is_gen & np.isin(app, list(targeted)))
    for i in cand:
        if not len(conns):
            break
        ts, end = df.at[i, TS], df.at[i, END_TS]
        m = conns[(conns["lport"] == my_port[i]) & (conns["app"] == app[i])]
        m = m[(m["open"] - sb <= ts) & (ts <= m["close"] + sa)]
        if len(m) != 1:
            reason[i] = "no logged connection" if m.empty else f"{len(m)} connections match"
            continue
        conn_id[i] = int(m["cid"].iloc[0])
        if pd.isna(ts) or ts < w0 or end > w1:
            status[i], reason[i] = "crosses_boundary", "flow extends past the session time window"
            continue
        status[i], reason[i] = SESSION_TRAFFIC, ""

    # invalid rows, then exact duplicates (every original CSV column identical)
    feats = [c for c in (features or []) if c in df.columns]
    invalid = df[TS].isna() | (dur < 0)
    if feats:
        invalid |= df[feats].apply(pd.to_numeric, errors="coerce").isna().all(axis=1)
    status[invalid.to_numpy()] = "invalid"
    original = [c for c in flows.columns]
    dup = flows.reset_index(drop=True).duplicated(subset=original, keep="first").to_numpy() & ~invalid.to_numpy()
    status[dup] = "duplicate"

    cap = meta.get("capture") or {}
    if cap.get("started_at") and cap.get("ended_at"):
        e = pd.Timedelta(seconds=lcfg["capture_edge_s"])
        df[EDGE] = (df[TS] < pd.Timestamp(cap["started_at"]) + e) | (df[END_TS] > pd.Timestamp(cap["ended_at"]) - e)
    else:
        df[EDGE] = False

    df[STATUS], df[REASON], df[CONN] = status, reason, conn_id
    label = pd.array([pd.NA] * n, dtype="Int64")
    st = pd.Series(status)
    label[st.isin(BACKGROUND).to_numpy()] = 0
    label[(st == SESSION_TRAFFIC).to_numpy()] = int(meta["label"])
    df[LABEL] = label
    return df


def label_session_files(root: Path, meta: dict[str, Any], lcfg: dict[str, Any],
                        features: list[str] | None = None) -> pd.DataFrame:
    sid = meta["session_id"]
    flows = read_flow_csv(root / meta["flows_csv"])
    conns = json.loads((root / meta["connections_file"]).read_text())
    pods_file = root / "raw" / f"{sid}.pods.json"
    pod_map = json.loads(pods_file.read_text()) if pods_file.is_file() else {}
    return label_session(flows, meta, conns, lcfg, pod_map, features)
