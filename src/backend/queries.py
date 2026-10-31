"""Read-only queries over the SQLite knowledge base and model artifacts.

Shared by the FastAPI backend and, as a fallback when the backend is down, by
the Streamlit dashboard, so stored records remain viewable without the cluster.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from src.utils import db
from src.utils.config import get_path, load_config


def _records(df: pd.DataFrame) -> list[dict[str, Any]]:
    return df.astype(object).where(df.notna(), None).to_dict(orient="records")


def _q(sql: str, params: tuple = (), cfg=None) -> list[dict[str, Any]]:
    with db.connect(db.db_path(cfg)) as c:
        return _records(db.query_df(c, sql, params))


def detections(limit: int = 200, offset: int = 0, source: str | None = None, predicted_class: str | None = None,
               src_ip: str | None = None, dst_ip: str | None = None, malicious: bool | None = None,
               cfg=None) -> list[dict[str, Any]]:
    where, params = ["simulated = 0"], []
    for col, val in (("source", source), ("predicted_class", predicted_class), ("src_ip", src_ip), ("dst_ip", dst_ip)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    if malicious is not None:
        where.append("is_malicious = ?")
        params.append(int(malicious))
    sql = f"SELECT * FROM detections WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ? OFFSET ?"
    return _q(sql, (*params, int(limit), int(offset)), cfg)


def detection_stats(cfg=None) -> dict[str, Any]:
    with db.connect(db.db_path(cfg)) as c:
        by_class = db.query_df(c, "SELECT source, predicted_class, is_malicious, COUNT(*) n, AVG(confidence) mean_conf "
                                  "FROM detections WHERE simulated = 0 GROUP BY 1, 2, 3")
        timeline = db.query_df(c, "SELECT substr(detected_at, 1, 16) minute, source, "
                                  "SUM(is_malicious) malicious, COUNT(*) - SUM(is_malicious) benign "
                                  "FROM detections WHERE simulated = 0 GROUP BY 1, 2 ORDER BY 1")
        conf = db.query_df(c, "SELECT predicted_class, CAST(confidence * 10 AS INTEGER) / 10.0 bucket, COUNT(*) n "
                              "FROM detections WHERE simulated = 0 GROUP BY 1, 2")
    return {"by_class": _records(by_class), "timeline": _records(timeline), "confidence": _records(conf)}


def metrics(cfg=None) -> dict[str, Any]:
    cfg = cfg or load_config()
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    medium = cfg["deception"]["thresholds"]["medium_confidence"]
    with db.connect(db.db_path(cfg)) as c:
        one = lambda sql, p=(): c.execute(sql, p).fetchone()[0]
        out = {
            "total_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0"),
            "benign_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND is_malicious = 0 "
                                "AND COALESCE(status, 'benign') != 'unknown'"),
            # attack verdicts on services without a benign profile: shown, never acted on
            "unknown_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND status = 'unknown'"),
            "malicious_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND is_malicious = 1"),
            "flows_by_source": dict(c.execute("SELECT source, COUNT(*) FROM detections WHERE simulated = 0 GROUP BY 1").fetchall()),
            "flow_bursts": one("SELECT COUNT(*) FROM behavior_alerts"),
            "behavior_alerts_by_type": dict(c.execute(
                "SELECT COALESCE(alert_type, 'flow_burst'), COUNT(*) FROM behavior_alerts GROUP BY 1").fetchall()),
            # distinct live-traffic sources with confident ML detections or flow bursts in the last 15 minutes
            # (historical dataset replays are not threats to this cluster)
            "active_threats": one(
                "SELECT COUNT(DISTINCT src_ip) FROM (SELECT src_ip FROM detections WHERE simulated = 0 AND is_malicious = 1 "
                "AND source IN ('pcap', 'live') AND confidence >= ? AND detected_at >= ? "
                "UNION SELECT src_ip FROM behavior_alerts WHERE detected_at >= ?)",
                (medium, since, since)),
            "active_decoys": one("SELECT COUNT(*) FROM decoys WHERE status IN ('deploying', 'active')"),
            "total_interactions": one("SELECT COUNT(*) FROM interactions"),
            "decisions": one("SELECT COUNT(*) FROM decisions"),
            "simulated_events": one("SELECT COUNT(*) FROM simulated_events"),
            "captures": one("SELECT COUNT(*) FROM captures"),
        }
    perf = model_performance(cfg)
    out["model"] = {"name": perf.get("name"), "accuracy": (perf.get("test") or {}).get("accuracy"),
                    "f1_macro": (perf.get("test") or {}).get("f1_macro")}
    return out


def behavior_alerts(limit: int = 200, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM behavior_alerts ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def decisions(limit: int = 200, action: str | None = None, include_simulated: bool = True, cfg=None) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if action:
        where.append("action = ?")
        params.append(action)
    if not include_simulated:
        where.append("simulated = 0")
    rows = _q(f"SELECT * FROM decisions WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", (*params, int(limit)), cfg)
    for r in rows:
        r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else None
    return rows


def decoys(limit: int = 200, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM decoys ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def interactions(limit: int = 200, decoy_name: str | None = None, cfg=None) -> list[dict[str, Any]]:
    if decoy_name:
        return _q("SELECT * FROM interactions WHERE decoy_name = ? ORDER BY ts DESC LIMIT ?", (decoy_name, int(limit)), cfg)
    return _q("SELECT * FROM interactions ORDER BY ts DESC LIMIT ?", (int(limit),), cfg)


def interaction_summary(src_ip: str | None = None, cfg=None) -> list[dict[str, Any]]:
    """Per (source, decoy) interaction summaries with a behaviour category."""
    from src.deception.profiling import summarize

    cfg = cfg or load_config()
    with db.connect(db.db_path(cfg)) as c:
        df = db.query_df(c, "SELECT * FROM interactions" + (" WHERE src_ip = ?" if src_ip else ""),
                         (src_ip,) if src_ip else ())
    return summarize(df, cfg["deception"]["profiling"])


def simulated_events(limit: int = 100, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM simulated_events ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def captures(limit: int = 100, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM captures ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def controller_snapshot(cfg=None) -> dict[str, Any]:
    """Stored controller state (used when the backend, and thus the live controller, is down)."""
    with db.connect(db.db_path(cfg)) as c:
        enabled = db.kv_get(c, "deception_enabled") == "1"
        last = db.kv_get(c, "last_cycle")
    return {"enabled": enabled, "stage": "unknown (backend offline)", "loop_running": False,
            "last_cycle": json.loads(last) if last else None,
            "active_decoys": _q("SELECT * FROM decoys WHERE status IN ('deploying', 'active')", (), cfg)}


def policy(cfg=None) -> dict[str, Any]:
    d = (cfg or load_config())["deception"]
    return {k: d[k] for k in ("attack_policy", "behavior_policy", "profiles", "thresholds", "scale_on_repeat",
                              "max_active_decoys", "max_replicas", "decoy_ttl_seconds", "max_lifetime_seconds",
                              "cooldown_seconds", "redeploy_cooldown_seconds", "act_on_sources", "engagement")}


def model_metrics(name: str, cfg=None) -> dict[str, Any] | None:
    """metrics.json of a registered model (name must be a registry key)."""
    cfg = cfg or load_config()
    models_dir = get_path("models_dir", cfg)
    reg = models_dir / "registry.json"
    if not reg.exists() or name not in json.loads(reg.read_text()):
        return None
    path = models_dir / name / "metrics.json"
    return json.loads(path.read_text()) if path.exists() else None


def evaluation_reports(cfg=None) -> dict[str, Any]:
    """Compact view of the evaluation reports (model comparison, behavioural replay, unknown traffic)."""
    cfg = cfg or load_config()
    rep = get_path("reports_dir", cfg)

    def load(name):
        p = rep / name
        return json.loads(p.read_text()) if p.exists() else None

    def test_summary(e):
        t, g, pr, lab = e["test"], e.get("grouped", {}), e.get("profile", {}), e.get("lab", {})
        return {"name": e["name"], "f1_macro": t["f1_macro"], "recall_macro": t["recall_macro"],
                "precision_macro": t["precision_macro"], "accuracy": t["accuracy"], "f1_weighted": t["f1_weighted"],
                "benign_fpr": t["binary"]["false_positive_rate"], "attack_recall": t["binary"]["detection_rate"],
                "per_class": t["per_class"], "labels": t["labels"], "confusion_matrix": t["confusion_matrix"],
                "lab": lab, "loco_mean_fpr": g.get("benign_loco_mean_fpr"),
                "loro": g.get("recon_loro"), "model_mb": pr.get("model_bytes", 0) / 1e6,
                "peak_rss_mb": pr.get("peak_rss_mb"), "single_flow_ms": pr.get("single_flow_median_ms")}

    out: dict[str, Any] = {"selected_model": cfg["experiments"].get("selected_model"),
                           "active_model": cfg["detection"]["active_model"]}
    mc = load("model_comparison.json")
    if mc:
        out["comparison"] = {"protocol": {k: mc["protocol"][k] for k in ("test_rows", "test_class_counts",
                                                                         "lab_train_sets", "lab_eval_sets")},
                             "baseline": test_summary(mc["baseline"]),
                             "candidates": [test_summary(e) for e in mc["candidates"].values()]}
    bd = load("behavioural_detection.json")
    if bd:
        out["behaviour"] = [{"name": s["name"], "role": s["role"], "windows": s["windows"],
                             "results": {d: {k: r[k] for k in ("detection_rate", "false_positive_rate", "precision",
                                                               "alerts_per_window_mean")}
                                         | {"scenarios": {n: {"windows": v["windows"], "delay_s": v["delay_s"],
                                                              "rate_per_s": v["rate_per_s"]}
                                                          for n, v in r["scenarios"].items()}}
                                         for d, r in s["results"].items()},
                             "flow_level_ml": s.get("flow_level_ml")} for s in bd["sessions"]]
    ut = load("unknown_traffic.json")
    if ut:
        out["unknown"] = {"config": cfg["detection"]["unknown"],
                          "folds": [{"application": f["application"],
                                     "variants": {v: {"held_out_fpr": x["held_out_app_benign"]["false_positive"],
                                                      "held_out_unknown": x["held_out_app_benign"]["unknown"],
                                                      "known_unknown": x["known_app_benign"]["unknown"],
                                                      "attacks_detected": x["attacks"]["detected"],
                                                      "attacks_unknown": x["attacks"]["unknown"]}
                                                  for v, x in f["variants"].items()}} for f in ut["folds"]]}
    return out


def model_performance(cfg=None) -> dict[str, Any]:
    cfg = cfg or load_config()
    models_dir = get_path("models_dir", cfg)
    path = models_dir / cfg["detection"]["active_model"] / "metrics.json"
    out = json.loads(path.read_text()) if path.exists() else {"error": f"{path} not found"}
    reg = models_dir / "registry.json"
    out["registry"] = json.loads(reg.read_text()) if reg.exists() else {}
    lab = get_path("reports_dir", cfg) / "lab_validation.json"
    out["lab_validation"] = json.loads(lab.read_text()) if lab.exists() else None
    return out
