import copy

import pandas as pd
import pytest

from src.preprocessing.dataset import (
    CAPTURE,
    DatasetValidationError,
    capture_id,
    capture_prefix,
    discover_capture_files,
    load_dataset,
)
from src.preprocessing.schema import LABEL
from src.utils.config import get_path
from tests.conftest import requires_dataset


def test_capture_id_parsing(tmp_path):
    p = tmp_path / "grafana_20230320T1603.pcap_Flow.csv"
    assert capture_id(p) == "grafana_20230320T1603"
    assert capture_prefix("rce-reverse-shell_20230319T1710") == "rce-reverse-shell"


@requires_dataset
def test_all_captures_discovered(cfg):
    files = discover_capture_files(cfg)
    prefixes = {capture_prefix(capture_id(f)) for f in files}
    assert prefixes == set(cfg["dataset"]["expected_capture_labels"])
    assert len(files) == 14


@requires_dataset
def test_label_mapping_matches_readme(dataset, cfg):
    assert sorted(dataset[LABEL].unique()) == list(range(11))
    for cap, g in dataset.groupby(CAPTURE):
        assert g[LABEL].nunique() == 1
        assert g[LABEL].iloc[0] == cfg["dataset"]["expected_capture_labels"][capture_prefix(cap)]


@requires_dataset
def test_combined_files_are_concatenations(dataset, cfg):
    """benign.csv / malicious.csv duplicate the per-capture files, so they are not loaded."""
    root = get_path("dataset_dir", cfg)
    assert len(pd.read_csv(root / "benign.csv", usecols=[LABEL])) == int((dataset[LABEL] == 0).sum())
    assert len(pd.read_csv(root / "malicious.csv", usecols=[LABEL])) == int((dataset[LABEL] != 0).sum())


def test_label_mismatch_is_rejected(tmp_path, cfg):
    bad = copy.deepcopy(cfg)
    bad["paths"]["dataset_dir"] = str(tmp_path)
    bad["dataset"]["capture_globs"] = ["*.pcap_Flow.csv"]
    (tmp_path / "reconnaissance_20230101T0000.pcap_Flow.csv").write_text(
        "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Label\n"
        "a,10.0.0.1,1,10.0.0.2,1880,6,2023-01-01 00:00:00.0,5,0\n"
    )
    with pytest.raises(DatasetValidationError, match="expected label 2"):
        load_dataset(bad)
