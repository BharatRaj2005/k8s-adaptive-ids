import copy
import json

import pytest

from src.detection.models import PcaAutoencoderNB, build_model
from src.detection.train import run_training
from tests.conftest import requires_dataset

ARTIFACTS = ["model.joblib", "preprocessor.joblib", "class_mapping.json", "feature_schema.json",
             "metrics.json", "training_config.json", "confusion_matrix.csv"]


def test_unknown_model_rejected():
    with pytest.raises(ValueError):
        build_model("svm", {}, 0)


def test_lightgbm_importable():
    model = build_model("lightgbm", {"n_estimators": 20, "min_child_samples": 1, "verbose": -1}, 0)
    model.fit([[0.0], [1.0], [0.1], [0.9], [0.2], [0.8]], [0, 1, 0, 1, 0, 1])
    assert list(model.predict([[0.0], [1.0]])) == [0, 1]


def test_pca_ae_nb_fits():
    import numpy as np

    rng = np.random.default_rng(0)
    X = np.vstack([rng.normal(0, 1, (60, 6)), rng.normal(4, 1, (60, 6))])
    y = np.array([0] * 60 + [1] * 60)
    m = PcaAutoencoderNB(pca_components=4, hidden_units=8, bottleneck_units=3, max_iter=300).fit(X, y)
    proba = m.predict_proba(X)
    assert proba.shape == (120, 2)
    assert (m.predict(X) == y).mean() > 0.8


@requires_dataset
@pytest.mark.parametrize("model_name", ["lightgbm", "extratrees", "pca_ae_nb"])
def test_training_saves_artifacts(model_name, small_dataset, fast_cfg, tmp_path):
    res = run_training(model_name, "dataset", "temporal", cfg=fast_cfg, df=small_dataset,
                       models_dir=tmp_path / "models", processed_dir=tmp_path / "processed", benign_holdout=None)
    out = tmp_path / "models" / res["name"]
    for f in ARTIFACTS:
        assert (out / f).is_file(), f
    m = res["test"]
    for key in ["accuracy", "precision_macro", "recall_macro", "f1_macro", "f1_weighted"]:
        assert 0.0 <= m[key] <= 1.0
    assert len(m["confusion_matrix"]) == len(m["labels"]) == 11
    assert res["latency"]["single_flow_median_ms"] > 0
    assert json.loads((out / "class_mapping.json").read_text())["benign_label"] == 0
    assert (tmp_path / "models" / "registry.json").is_file()


@requires_dataset
def test_attack_focused_policy_drops_background_like_flows(small_dataset, fast_cfg, tmp_path):
    cfg = copy.deepcopy(fast_cfg)
    cfg["training"]["attack_focused"]["min_service_port_count"] = 3  # small background sample
    res = run_training("extratrees", "attack_focused", "temporal", cfg=cfg, df=small_dataset,
                       models_dir=tmp_path / "m", processed_dir=tmp_path / "p", benign_holdout=None)
    rep = res["label_policy_report"]
    assert rep["dropped_background_like_attack_flows"] > 0
    assert 10 in rep["dropped_classes"]  # CVE-2019-5736 has no attack-specific flows
    assert 0 in res["test"]["labels"] and 2 in res["test"]["labels"]
