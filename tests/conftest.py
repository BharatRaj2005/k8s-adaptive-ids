from __future__ import annotations

import copy
from pathlib import Path

import pytest

from src.preprocessing.dataset import CAPTURE, discover_capture_files, load_dataset
from src.utils.config import load_config

FIXTURES = Path(__file__).parent / "fixtures"


def _dataset_available() -> bool:
    try:
        return bool(discover_capture_files())
    except FileNotFoundError:
        return False


requires_dataset = pytest.mark.skipif(not _dataset_available(), reason="kubernetes-dataset not cloned")


@pytest.fixture(scope="session")
def cfg():
    return copy.deepcopy(load_config())


@pytest.fixture(scope="session")
def dataset(cfg):
    if not _dataset_available():
        pytest.skip("kubernetes-dataset not cloned")
    return load_dataset(cfg)


@pytest.fixture(scope="session")
def small_dataset(dataset):
    """Up to 300 flows per capture, keeping every class and the time order."""
    return dataset.groupby(CAPTURE, group_keys=False).head(300).reset_index(drop=True)


@pytest.fixture(scope="session")
def fast_cfg(cfg):
    c = copy.deepcopy(cfg)
    c["models"]["lightgbm"]["n_estimators"] = 40
    c["models"]["extratrees"]["n_estimators"] = 40
    c["models"]["pca_ae_nb"]["max_iter"] = 20
    c["training"]["latency_samples"] = 20
    return c


@pytest.fixture(scope="session")
def trained_model_dir(small_dataset, fast_cfg, tmp_path_factory):
    from src.detection.train import run_training

    models_dir = tmp_path_factory.mktemp("models")
    res = run_training("extratrees", "dataset", "temporal", name="test_model", cfg=fast_cfg,
                       df=small_dataset, models_dir=models_dir,
                       processed_dir=tmp_path_factory.mktemp("processed"), benign_holdout=None)
    return models_dir / res["name"]
