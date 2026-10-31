import numpy as np
import pandas as pd

from src.detection.unknown import UNKNOWN, NoveltyScorer, assess, benign_service_profile, service_keys
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, PROTOCOL, SRC_IP, SRC_PORT

UCFG = {"checks": ["unfamiliar_service", "low_confidence", "out_of_distribution"],
        "min_benign_service_flows": 2, "min_confidence": 0.5}


def flows(ports, labels):
    return pd.DataFrame({SRC_IP: "10.0.0.1", SRC_PORT: 40000 + np.arange(len(ports)), DST_IP: "10.0.0.2",
                         DST_PORT: ports, PROTOCOL: 6, LABEL: labels})


def test_service_profile_counts_benign_flows_per_service():
    prof = benign_service_profile(flows([1880, 1880, 3000, 1880], [0, 0, 0, 2]), 0)
    assert prof == {"6:1880": 2, "6:3000": 1}


def test_attack_verdict_on_unfamiliar_service_becomes_unknown():
    prof = {"6:1880": 10}
    svc = service_keys(flows([1880, 3000, 3000], [0, 0, 0]))
    st, why = assess(np.array([2, 2, 0]), np.array([0.95, 0.95, 0.9]), svc, 0,
                     {**UCFG, "checks": ["unfamiliar_service"]}, prof)
    assert st.tolist() == ["attack", UNKNOWN, "benign"]      # benign verdicts are not touched by this check
    assert why.tolist() == ["", "unfamiliar_service", ""]


def test_low_confidence_and_novelty():
    svc = service_keys(flows([1880, 1880, 1880], [0, 0, 0]))
    st, why = assess(np.array([2, 2, 0]), np.array([0.4, 0.95, 0.9]), svc, 0, UCFG, {"6:1880": 10},
                     novelty=np.array([0.1, 0.1, 9.0]), novelty_threshold=1.0)
    assert st.tolist() == [UNKNOWN, "attack", UNKNOWN]
    assert why.tolist() == ["low_confidence", "", "out_of_distribution"]


def test_no_checks_keeps_classifier_verdicts():
    svc = service_keys(flows([9999], [0]))
    st, _ = assess(np.array([2]), np.array([0.1]), svc, 0, {**UCFG, "checks": []}, {}, np.array([99.0]), 1.0)
    assert st.tolist() == ["attack"]


def test_novelty_scorer_flags_far_points_only():
    rng = np.random.default_rng(0)
    train = pd.DataFrame(rng.normal(100, 5, size=(400, 3)), columns=list("abc"))
    y = np.zeros(400, dtype=int)
    s = NoveltyScorer(k=3, sample=1000).fit(train, y, 0)
    thr = s.calibrate(pd.DataFrame(rng.normal(100, 5, size=(200, 3)), columns=list("abc")), 0.99)
    far = s.score(pd.DataFrame([[1e6, 1e6, 1e6]], columns=list("abc")))
    near = s.score(pd.DataFrame([[100, 100, 100]], columns=list("abc")))
    assert far[0] > thr > near[0]
