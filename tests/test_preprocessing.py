import numpy as np
import pandas as pd

from src.detection.train import feature_columns
from src.preprocessing.cleaning import background_service_signatures, label_noise_analysis
from src.preprocessing.dataset import CAPTURE, TS, capture_prefix
from src.preprocessing.pipeline import FlowFeatureCleaner, build_preprocessor
from src.preprocessing.schema import LABEL, align_features, read_flow_csv
from src.preprocessing.splitting import TEST, TRAIN, temporal_split
from tests.conftest import FIXTURES, requires_dataset


def test_repeated_header_rows_are_dropped():
    df = read_flow_csv(FIXTURES / "local_cicflowmeter_cni0.csv")
    assert len(df) == 2  # file has the header twice plus two flows
    assert df["Src IP"].tolist() == ["10.42.0.1", "10.42.0.1"]
    assert pd.api.types.is_numeric_dtype(df["Flow Duration"])


def test_bad_numeric_cells_become_nan(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("Flow ID, Src IP ,Flow Duration,Flow Bytes/s\nf1,1.1.1.1,10,Infinity\nf2,1.1.1.2,oops,5\n")
    df = read_flow_csv(p)
    assert list(df.columns) == ["Flow ID", "Src IP", "Flow Duration", "Flow Bytes/s"]
    assert np.isinf(df["Flow Bytes/s"].iloc[0])
    assert np.isnan(df["Flow Duration"].iloc[1])


def test_preprocessor_handles_inf_and_nan():
    train = pd.DataFrame({"a": [1.0, np.inf, 3.0, 5.0], "b": [np.nan, 2.0, 2.0, 4.0], "c": [7, 7, 7, 7]})
    pre = build_preprocessor(correlation_threshold=None)
    out = pre.fit_transform(train)
    assert list(out.columns) == ["a", "b"]  # constant column dropped
    assert np.isfinite(out.to_numpy()).all()
    assert out["a"].iloc[1] == 3.0  # median of finite training values


def test_preprocessor_is_fitted_on_training_data_only():
    train = pd.DataFrame({"a": [1.0, 2.0, 3.0], "const": [0.0, 0.0, 0.0]})
    test = pd.DataFrame({"a": [np.nan, 100.0], "const": [5.0, 9.0]})
    pre = build_preprocessor(correlation_threshold=None).fit(train)
    out = pre.transform(test)
    assert "const" not in out.columns  # selection decided on train, not test
    assert out["a"].iloc[0] == 2.0  # imputed with the training median


def test_correlated_features_are_dropped():
    x = np.arange(50, dtype=float)
    df = pd.DataFrame({"x": x, "x2": x * 2 + 1, "noise": np.random.default_rng(0).normal(size=50)})
    cleaner = FlowFeatureCleaner(correlation_threshold=0.99).fit(df)
    assert cleaner.dropped_correlated_ == ["x2"]
    assert cleaner.selected_features_ == ["x", "noise"]


def test_align_features_reports_missing():
    df = pd.DataFrame({"flow duration": [1.0], "Extra": [2.0]})
    X, missing = align_features(df, ["Flow Duration", "Fwd Packet Length Max"])
    assert list(X.columns) == ["Flow Duration", "Fwd Packet Length Max"]
    assert X["Flow Duration"].iloc[0] == 1.0
    assert missing == ["Fwd Packet Length Max"]


@requires_dataset
def test_feature_columns_exclude_leaky_fields(dataset, cfg):
    feats = feature_columns(dataset, cfg)
    for leaky in ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Src Port", "Total TCP Flow Time", LABEL]:
        assert leaky not in feats
    assert "Dst Port" in feats and "Flow Duration" in feats
    assert not any(c.startswith("_") for c in feats)


@requires_dataset
def test_feature_schema_matches_local_cicflowmeter(dataset, cfg):
    """Every model input feature exists in the local CICFlowMeter build's output."""
    local = read_flow_csv(FIXTURES / "local_cicflowmeter_cni0.csv")
    _, missing = align_features(local, feature_columns(dataset, cfg))
    assert missing == []


@requires_dataset
def test_temporal_split_holds_out_latest_flows(small_dataset):
    split = temporal_split(small_dataset, 0.25)
    for _, g in small_dataset.assign(_s=split).groupby(CAPTURE):
        assert set(g["_s"]) == {TRAIN, TEST}
        assert g.loc[g["_s"] == TRAIN, TS].max() <= g.loc[g["_s"] == TEST, TS].min()


@requires_dataset
def test_label_noise_analysis(dataset, cfg):
    bg = dataset[dataset[CAPTURE].map(capture_prefix) == "background_traffic"]
    sigs = background_service_signatures(bg, 20)
    assert "6:6642" in sigs and "17:53" in sigs
    assert "6:1880" not in sigs  # Node-RED port is not background
    noise = label_noise_analysis(dataset, sigs, 0)["per_class"]
    assert noise[2]["background_like_fraction"] < 0.2   # reconnaissance: real attack traffic
    assert noise[10]["background_like_fraction"] > 0.9  # runc escape: no attack-specific flows
