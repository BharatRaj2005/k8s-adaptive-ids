"""Evidence-based per-flow labels for the Kubernetes misuse-detection dataset.

The published dataset assigns the scenario label to every flow of an attack
capture. Those captures are whole-node captures, so most of their flows are DNS,
CoreDNS health checks, OVN database and API-server traffic that would exist
without the attack. This module labels each flow of an attack capture from
evidence inside the capture and the scenario definition in config (`labeling`):

  attack      direct      - flow to the scenario's target application port.
                            Valid because no benign workload runs during attack
                            captures; `application_port_idle_check` verifies
                            that application ports are silent in captures whose
                            scenario does not target them.
              post_compromise - connection opened by the attacked pod when that
                            pod never opens connections as a client in any
                            benign capture (reverse shell, API-server access).
  background  infrastructure (protocol:port) signature of the pure background
              capture, or an exact client/server/service tuple seen in a benign
              capture - and not involving any endpoint of the attack.
  ambiguous   everything else. Kept for reporting, never used for training.

No label is derived from an address or port alone: a port is only evidence for
a scenario that targets the application listening on it, and an address only
becomes an attack endpoint through such a flow.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.cleaning import background_service_signatures
from src.preprocessing.dataset import CAPTURE, capture_prefix
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, PROTOCOL, SRC_IP, SRC_PORT

ORIGINAL_LABEL = "_label_original"
STATUS = "_label_status"        # benign | attack | background | ambiguous
EVIDENCE = "_label_evidence"    # benign_capture | direct | post_compromise | infrastructure | benign_tuple | none

ATTACK, BACKGROUND, AMBIGUOUS, BENIGN = "attack", "background", "ambiguous", "benign"
OBSERVABILITY = ("network", "kubernetes_api", "host_runtime")


def orient(df: pd.DataFrame) -> pd.DataFrame:
    """Client, server and service port per flow; the lower port is taken as the service."""
    dst_is_server = df[DST_PORT].fillna(-1) <= df[SRC_PORT].fillna(-1)
    return pd.DataFrame({
        "client": np.where(dst_is_server, df[SRC_IP], df[DST_IP]),
        "server": np.where(dst_is_server, df[DST_IP], df[SRC_IP]),
        "service": np.where(dst_is_server, df[DST_PORT], df[SRC_PORT]).astype("int64"),
        "proto": df[PROTOCOL].astype("int64"),
    }, index=df.index)


def _keys(o: pd.DataFrame, cols: list[str]) -> pd.Series:
    return o[cols].astype(str).agg("|".join, axis=1)


def scenario_for(capture: str, cfg: dict[str, Any]) -> dict[str, Any] | None:
    return cfg["labeling"]["scenarios"].get(capture_prefix(capture))


def label_dataset(df: pd.DataFrame, cfg: dict[str, Any], signature_source: pd.DataFrame | None = None) -> pd.DataFrame:
    """Add ORIGINAL_LABEL, STATUS and EVIDENCE columns; LABEL becomes the evidence label.

    `signature_source` is the background capture subset used to learn
    infrastructure signatures (pass the training part to keep test flows out of it).
    Ambiguous flows keep their original label in LABEL; filter on STATUS.
    """
    lab = cfg["labeling"]
    benign = cfg["benign_label"]
    out = df.copy()
    out[ORIGINAL_LABEL] = out[LABEL]
    out[STATUS] = BENIGN
    out[EVIDENCE] = "benign_capture"
    o = orient(out)

    is_benign_cap = out[LABEL] == benign
    if signature_source is None:
        bg_prefix = cfg["dataset"]["background_capture_prefix"]
        signature_source = out[out[CAPTURE].map(capture_prefix) == bg_prefix]
    signatures = background_service_signatures(signature_source, lab["background_min_service_count"])
    sig_key = o["proto"].astype(str) + ":" + o["service"].astype(str)

    tuple_cols = ["client", "server", "proto", "service"]
    tup = _keys(o, tuple_cols)
    benign_tuples = set(tup[is_benign_cap])
    benign_clients = set(o.loc[is_benign_cap, "client"])
    benign_endpoints = benign_clients | set(o.loc[is_benign_cap, "server"])

    for cap, idx in out[~is_benign_cap].groupby(CAPTURE).groups.items():
        sc = scenario_for(cap, cfg)
        if sc is None:
            raise ValueError(f"capture {cap} has no labeling scenario in config")
        g = o.loc[idx]
        status = pd.Series(AMBIGUOUS, index=idx, dtype=object)
        evidence = pd.Series("none", index=idx, dtype=object)

        direct = g["service"].isin(sc.get("target_ports") or [])
        targets = set(g.loc[direct, "server"])
        post = pd.Series(False, index=idx)
        if sc.get("post_compromise") and targets:
            post = g["client"].isin(targets - benign_clients) & ~direct
        attack = direct | post
        # Attack endpoints: the attacked pods plus peers they reached that never
        # occur in benign data. Shared infrastructure (e.g. the API-server node)
        # stays out, so its unrelated traffic can still be confirmed as background.
        involved = targets | (set(g.loc[post, "server"]) - benign_endpoints)

        touches = g["client"].isin(involved) | g["server"].isin(involved)
        infra = sig_key.loc[idx].isin(signatures) & ~touches
        seen = tup.loc[idx].isin(benign_tuples) & ~touches

        status[seen | infra] = BACKGROUND
        evidence[seen] = "benign_tuple"
        evidence[infra] = "infrastructure"
        status[attack] = ATTACK
        evidence[direct] = "direct"
        evidence[post] = "post_compromise"
        out.loc[idx, STATUS] = status
        out.loc[idx, EVIDENCE] = evidence

    if lab["background_action"] == "benign":
        out.loc[out[STATUS] == BACKGROUND, LABEL] = benign
    elif lab["background_action"] != "exclude":
        raise ValueError(f"unknown background_action {lab['background_action']!r}")
    return out


def trainable_mask(labelled: pd.DataFrame, cfg: dict[str, Any]) -> pd.Series:
    """Flows that may be used for supervised training/evaluation."""
    keep = labelled[STATUS].isin([BENIGN, ATTACK])
    if cfg["labeling"]["background_action"] == "benign":
        keep |= labelled[STATUS] == BACKGROUND
    return keep


def supported_classes(labelled: pd.DataFrame, cfg: dict[str, Any]) -> tuple[list[int], dict[int, int]]:
    """Attack classes with enough attack-evidence flows to be trained, plus all counts."""
    counts = labelled.loc[labelled[STATUS] == ATTACK, LABEL].value_counts()
    all_counts = {int(c): int(counts.get(c, 0)) for c in sorted(labelled[ORIGINAL_LABEL].unique()) if c != cfg["benign_label"]}
    ok = [c for c, n in all_counts.items() if n >= cfg["labeling"]["min_class_flows"]]
    return ok, all_counts


def application_port_idle_check(df: pd.DataFrame, cfg: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Flows per application port in attack captures whose scenario does not target that port.

    All zeros support the assumption behind `direct` evidence: application ports
    see no traffic in attack captures except the attack itself.
    """
    o = orient(df)
    res: dict[str, dict[str, int]] = {}
    for cap, idx in df[df[LABEL] != cfg["benign_label"]].groupby(CAPTURE).groups.items():
        sc = scenario_for(cap, cfg) or {}
        other = [p for p in cfg["labeling"]["application_ports"] if p not in (sc.get("target_ports") or [])]
        svc = o.loc[idx, "service"]
        res[cap] = {str(p): int((svc == p).sum()) for p in other}
    return res


def attack_intervals(labelled: pd.DataFrame, ts_col: str) -> dict[str, dict[str, Any]]:
    """Time span of attack-evidence flows per capture (derived, not dataset metadata)."""
    res = {}
    for cap, g in labelled[labelled[STATUS] == ATTACK].groupby(CAPTURE):
        t = g[ts_col].dropna()
        res[cap] = {"first": str(t.min()) if len(t) else None, "last": str(t.max()) if len(t) else None,
                    "seconds": float((t.max() - t.min()).total_seconds()) if len(t) else None, "flows": int(len(g))}
    return res
