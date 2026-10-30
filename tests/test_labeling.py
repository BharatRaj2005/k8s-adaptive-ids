import copy

import pandas as pd
import pytest

from src.preprocessing.dataset import CAPTURE
from src.preprocessing.labeling import (
    AMBIGUOUS, ATTACK, BACKGROUND, BENIGN, EVIDENCE, ORIGINAL_LABEL, STATUS,
    application_port_idle_check, label_dataset, supported_classes, trainable_mask,
)
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, PROTOCOL, SRC_IP, SRC_PORT
from tests.conftest import requires_dataset

NODE, GW, NODERED, COREDNS, ATTACKER = "10.0.0.1", "100.64.0.2", "10.16.0.45", "10.16.0.6", "203.0.113.9"


def flow(cap, label, src, sport, dst, dport, proto=6):
    return {CAPTURE: cap, LABEL: label, SRC_IP: src, SRC_PORT: sport, DST_IP: dst, DST_PORT: dport, PROTOCOL: proto}


def frame(cfg):
    rows = []
    # pure background capture: CoreDNS (udp 53) and API-server traffic, both recurring
    for i in range(25):
        rows.append(flow("background_traffic_x", 0, "10.16.0.2", 40000 + i, COREDNS, 53, 17))
        rows.append(flow("background_traffic_x", 0, "10.16.0.3", 41000 + i, NODE, 6443))
    # benign app capture: users reach Node-RED through the ingress gateway
    rows += [flow("nodered_x", 0, GW, 50000 + i, NODERED, 1880) for i in range(5)]
    # RCE capture (targets :1880, post_compromise)
    rce = "rce-reverse-shell_x"
    rows += [
        flow(rce, 3, GW, 52000, NODERED, 1880),                 # exploit delivery -> direct
        flow(rce, 3, NODERED, 53000, ATTACKER, 9001),           # reverse shell -> post_compromise
        flow(rce, 3, NODERED, 53001, NODE, 6443),               # API access by the pod -> post_compromise
        flow(rce, 3, "10.16.0.3", 53002, NODE, 6443),           # ordinary API traffic -> background
        flow(rce, 3, "10.16.0.2", 53003, COREDNS, 53, 17),      # ordinary DNS -> background
        flow(rce, 3, "10.16.0.9", 53004, "198.51.100.1", 7000),  # unexplained -> ambiguous
    ]
    # InfluxDB scenario: a :1880 flow is NOT evidence for it (port belongs to another app)
    rows += [flow("cve201920933_x", 6, GW, 54000, "10.16.0.14", 8086),
             flow("cve201920933_x", 6, GW, 54001, NODERED, 1880)]
    # host-runtime CVE: only background
    rows += [flow("cve20195736_x", 10, "10.16.0.2", 55000 + i, COREDNS, 53, 17) for i in range(3)]
    return pd.DataFrame(rows)


@pytest.fixture()
def lcfg(cfg):
    c = copy.deepcopy(cfg)
    c["labeling"]["min_class_flows"] = 2
    return c


def status_of(df, i):
    return df.loc[i, STATUS], df.loc[i, EVIDENCE]


def test_rules_assign_attack_background_and_ambiguous(lcfg):
    df = frame(lcfg)
    out = label_dataset(df, lcfg)
    rce = out[out[CAPTURE] == "rce-reverse-shell_x"]
    got = [tuple(r) for r in rce[[STATUS, EVIDENCE]].to_numpy()]
    assert got == [(ATTACK, "direct"), (ATTACK, "post_compromise"), (ATTACK, "post_compromise"),
                   (BACKGROUND, "infrastructure"), (BACKGROUND, "infrastructure"), (AMBIGUOUS, "none")]
    assert (out.loc[out[CAPTURE] == "nodered_x", STATUS] == BENIGN).all()
    # original labels are preserved, background becomes benign, attacks keep their class
    assert rce[ORIGINAL_LABEL].tolist() == [3] * 6
    assert rce[LABEL].tolist()[:5] == [3, 3, 3, 0, 0]


def test_port_is_only_evidence_for_the_targeted_application(lcfg):
    out = label_dataset(frame(lcfg), lcfg)
    influx = out[out[CAPTURE] == "cve201920933_x"]
    # the :1880 flow is no attack evidence here; it matches a benign-capture tuple instead
    assert [tuple(r) for r in influx[[STATUS, EVIDENCE]].to_numpy()] == [(ATTACK, "direct"),
                                                                       (BACKGROUND, "benign_tuple")]


def test_shared_infrastructure_is_not_an_attack_endpoint(lcfg):
    """The pod's API call must not turn every other API-server flow into an attack-linked one."""
    out = label_dataset(frame(lcfg), lcfg)
    rce = out[out[CAPTURE] == "rce-reverse-shell_x"]
    other_api = rce[(rce[SRC_IP] == "10.16.0.3") & (rce[DST_PORT] == 6443)]
    assert other_api[STATUS].tolist() == [BACKGROUND]


def test_host_runtime_capture_has_no_attack_flows(lcfg):
    out = label_dataset(frame(lcfg), lcfg)
    host = out[out[CAPTURE] == "cve20195736_x"]
    assert (host[STATUS] == BACKGROUND).all()
    supported, counts = supported_classes(out, lcfg)
    assert counts[10] == 0 and 10 not in supported
    assert 3 in supported and 6 not in supported  # 6 has a single attack flow < min_class_flows


def test_ambiguous_flows_are_never_trainable(lcfg):
    out = label_dataset(frame(lcfg), lcfg)
    keep = trainable_mask(out, lcfg)
    assert not keep[out[STATUS] == AMBIGUOUS].any()
    assert keep[out[STATUS] == BACKGROUND].all()
    excl = copy.deepcopy(lcfg)
    excl["labeling"]["background_action"] = "exclude"
    out2 = label_dataset(frame(excl), excl)
    assert not trainable_mask(out2, excl)[out2[STATUS] == BACKGROUND].any()
    assert out2.loc[out2[STATUS] == BACKGROUND, LABEL].ne(0).all()  # keeps its original label


def test_signatures_can_come_from_training_part_only(lcfg):
    df = frame(lcfg)
    no_sigs = df[df[CAPTURE] == "background_traffic_x"].head(0)
    out = label_dataset(df, lcfg, signature_source=no_sigs)
    rce = out[out[CAPTURE] == "rce-reverse-shell_x"]
    assert (rce[EVIDENCE] != "infrastructure").all()


def test_idle_check_counts_non_targeted_application_ports(lcfg):
    res = application_port_idle_check(frame(lcfg), lcfg)
    assert res["cve201920933_x"]["1880"] == 1
    assert res["rce-reverse-shell_x"] == {"3000": 0, "8086": 0}


@requires_dataset
def test_real_dataset_labels(dataset, cfg):
    out = label_dataset(dataset, cfg)
    assert len(out) == len(dataset)
    attack = out[out[STATUS] == ATTACK]
    # recon: the 2206 Node-RED flows; host-runtime CVEs carry no network attack evidence
    assert (attack[ORIGINAL_LABEL] == 2).sum() == 2206
    assert not attack[ORIGINAL_LABEL].isin([7, 8, 9, 10]).any()
    assert all(v == 0 for ports in application_port_idle_check(dataset, cfg).values() for v in ports.values())
    assert (out.loc[out[ORIGINAL_LABEL] == 0, STATUS] == BENIGN).all()
