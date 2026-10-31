import pandas as pd
import pytest

from src.detection.predictor import PREDICTION_COLUMNS, FlowPredictor, to_records
from src.preprocessing.schema import SchemaError
from src.utils.config import get_path, load_config
from tests.conftest import FIXTURES, requires_dataset


@requires_dataset
def test_predict_dataset_csv(trained_model_dir, cfg):
    path = get_path("dataset_dir", cfg) / "malicious" / "cve202143798_20230309T0401.pcap_Flow.csv"
    pred = FlowPredictor(trained_model_dir).predict_csv(path, source="dataset")
    assert list(pred.columns) == PREDICTION_COLUMNS
    assert len(pred) == 36
    assert pred["confidence"].between(0, 1).all()
    assert (pred["is_malicious"] == (pred["predicted_label"] != 0)).all()
    assert (pred["true_label"] == 5).all()
    assert (pred["capture_file"] == path.name).all()
    assert pred["src_ip"].notna().all() and pred["timestamp"].notna().all()
    assert (pred["processing_time_ms"] > 0).all()


@requires_dataset
def test_predict_local_cicflowmeter_csv(trained_model_dir):
    predictor = FlowPredictor(trained_model_dir)
    pred = predictor.predict_csv(FIXTURES / "local_cicflowmeter_cni0.csv", source="pcap")
    assert predictor.last_report["missing_features"] == []
    assert pred["dst_ip"].tolist() == ["10.42.0.107", "10.42.0.112"]
    assert pred["true_label"].isna().all()  # "NeedManualLabel" is not a label


@requires_dataset
def test_missing_metadata_is_null_not_invented(trained_model_dir):
    predictor = FlowPredictor(trained_model_dir)
    df = pd.read_csv(FIXTURES / "local_cicflowmeter_cni0.csv", skiprows=[1])
    df = df.drop(columns=["Src IP", "Dst Port", "Timestamp"])
    rec = to_records(predictor.predict_frame(df, source="pcap"))[0]
    assert rec["src_ip"] is None and rec["dst_port"] is None and rec["timestamp"] is None
    assert rec["dst_ip"] == "10.42.0.107"
    assert isinstance(rec["confidence"], float) and isinstance(rec["is_malicious"], bool)


@requires_dataset
def test_too_many_missing_features_rejected(trained_model_dir):
    df = pd.DataFrame({"Src IP": ["1.1.1.1"], "Flow Duration": [10]})
    with pytest.raises(SchemaError):
        FlowPredictor(trained_model_dir).predict_frame(df)


def test_invalid_source_rejected(trained_model_dir):
    with pytest.raises(ValueError):
        FlowPredictor(trained_model_dir).predict_frame(pd.DataFrame({"a": [1]}), source="bogus")


def test_active_model_loads_if_trained():
    cfg = load_config()
    model_dir = get_path("models_dir", cfg) / cfg["detection"]["active_model"]
    if not (model_dir / "model.joblib").exists():
        pytest.skip("active model not trained yet")
    pred = FlowPredictor(model_dir).predict_csv(FIXTURES / "local_cicflowmeter_cni0.csv", source="pcap")
    assert len(pred) == 2


def test_unknown_handling_never_reports_unfamiliar_service_attacks(trained_model_dir, cfg, tmp_path):
    import json
    import shutil

    from src.detection.unknown import UNKNOWN, UNKNOWN_CLASS

    model = tmp_path / "m"
    shutil.copytree(trained_model_dir, model)
    from src.utils.config import get_path

    path = sorted((get_path("dataset_dir", cfg) / "malicious").glob("reconnaissance_*.csv"))[0]
    plain = FlowPredictor(model).predict_csv(path, source="dataset")
    assert plain["status"].isin(["benign", "attack"]).all() and plain["unknown_reason"].isna().all()
    # a profile without :1880 makes every attack verdict on Node-RED unfamiliar
    (model / "service_profile.json").write_text(json.dumps({"6:6642": 1000}))
    ucfg = {"enabled": True, "checks": ["unfamiliar_service"], "min_benign_service_flows": 50, "min_confidence": 0.5}
    pred = FlowPredictor(model, ucfg).predict_csv(path, source="dataset")
    on_1880 = (pred["dst_port"] == 1880) & plain["is_malicious"]
    assert on_1880.any()
    assert (pred.loc[on_1880, "status"] == UNKNOWN).all()
    assert (pred.loc[on_1880, "predicted_class"] == UNKNOWN_CLASS).all()
    assert not pred.loc[on_1880, "is_malicious"].any()            # never handed to the controller as an attack
    assert (pred["predicted_label"] == plain["predicted_label"]).all()  # the model's own label is kept
