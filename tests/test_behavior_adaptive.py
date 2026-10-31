import copy
import json

import pandas as pd
import pytest

from src.detection.adaptive_behavior import AdaptiveBehavior, learned_threshold

WIN = 10.0


def window(**sources):
    """sources: name -> (dst_ip, dst_port, flows)."""
    rows = []
    for src, (dst, port, n) in sources.items():
        rows += [{"src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": 6,
                  "is_malicious": False, "predicted_class": "Benign"}] * n
    return pd.DataFrame(rows, columns=["src_ip", "dst_ip", "dst_port", "protocol", "is_malicious", "predicted_class"])


@pytest.fixture()
def bcfg(cfg):
    c = copy.deepcopy(cfg)
    c["behavior"]["adaptive"].update(warmup=10, horizon_s=60)
    return c


def run(det, windows, t0=0.0):
    out = []
    for i, w in enumerate(windows):
        out.append(det.analyze(w, WIN, t0 + (i + 1) * WIN))
    return out


def benign():
    # a regular client with 1-2 flows per window and a kubelet probing one pod
    return window(client=("app", 1880, 1), kubelet=("app", 8081, 1))


def test_threshold_is_bounded_by_floor_and_fixed_level():
    assert learned_threshold([0.1] * 3, 4, 0.1, 0.5, 1.5, warmup=10) == (1.5, None)  # warm-up -> fixed level
    thr, med = learned_threshold([0.1] * 20, 4, 0.1, 0.5, 1.5, warmup=10)
    assert med == 0.1 and thr == 0.5                       # floor
    thr, _ = learned_threshold([5.0] * 20, 4, 0.1, 0.5, 1.5, warmup=10)
    assert thr == 1.5                                      # never above the fixed level


def test_fixed_rule_still_reported(bcfg):
    det = AdaptiveBehavior(bcfg)
    alerts = det.analyze(window(scanner=("app", 1880, 20)), WIN, 10.0)
    assert alerts["alert_type"].tolist() == ["flow_burst"]
    assert alerts["severity"].tolist() == ["high"]


def test_medium_rate_scan_found_only_after_learning(bcfg):
    det = AdaptiveBehavior(bcfg)
    early = det.analyze(window(scanner=("app", 1880, 8)), WIN, 10.0)
    assert early.empty                                      # warm-up: fixed level (15) applies
    run(det, [benign() for _ in range(12)], t0=10.0)
    alerts = det.analyze(window(client=("app", 1880, 1), scanner=("app", 1880, 8)), WIN, 200.0)
    assert alerts["src_ip"].tolist() == ["scanner"]
    assert alerts["alert_type"].tolist() == ["adaptive_rate"]
    assert alerts["severity"].tolist() == ["medium"]


def test_benign_traffic_raises_no_alert(bcfg):
    det = AdaptiveBehavior(bcfg)
    assert all(a.empty for a in run(det, [benign() for _ in range(30)]))


def test_slow_scan_over_horizon(bcfg):
    det = AdaptiveBehavior(bcfg)
    bcfg["behavior"]["adaptive"]["horizon_floor_flows"] = 10
    run(det, [benign() for _ in range(25)])            # horizon fills after 6 windows, then 19 learned values
    slow = [window(client=("app", 1880, 1), scanner=("app", 1880, 3)) for _ in range(8)]
    alerts = pd.concat(run(det, slow, t0=250.0))
    hits = alerts[alerts["src_ip"] == "scanner"]
    assert not hits.empty and set(hits["alert_type"]) == {"slow_scan"}
    assert json.loads(hits["details"].iloc[0])["horizon_flows"] >= 10
    assert "client" not in set(alerts["src_ip"])


def test_alerting_values_are_not_learned(bcfg):
    det = AdaptiveBehavior(bcfg)
    run(det, [benign() for _ in range(12)])
    before = list(det.state["rate"]["6:1880"])
    det.analyze(window(client=("app", 1880, 1), scanner=("app", 1880, 8)), WIN, 500.0)
    after = det.state["rate"]["6:1880"]
    assert after[-1] == 0.1 and len(after) == len(before) + 1   # only the client's value was added


def test_probes_to_many_destinations_are_not_summed(bcfg):
    """A kubelet probing many pods once each is not a slow scan of one service."""
    det = AdaptiveBehavior(bcfg)
    bcfg["behavior"]["adaptive"]["horizon_floor_flows"] = 5
    pods = [pd.concat([window(kubelet=(f"pod{i}", 8081, 1)) for i in range(6)]) for _ in range(20)]
    assert all(a.empty for a in run(det, pods))


def test_state_round_trips_as_json(bcfg):
    det = AdaptiveBehavior(bcfg)
    run(det, [benign() for _ in range(5)])
    again = AdaptiveBehavior(bcfg, json.loads(json.dumps(det.state)))
    assert again.state == det.state and again.thresholds()
