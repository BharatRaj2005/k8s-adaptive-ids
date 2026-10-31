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


# --- unified live monitoring -----------------------------------------------------------
# Only captured traffic (sources pcap/live); dataset replays and simulated deception events are excluded.
LIVE = "d.simulated = 0 AND d.source IN ('pcap', 'live')"
STATUS_SQL = "COALESCE(d.status, CASE WHEN d.is_malicious = 1 THEN 'attack' ELSE 'benign' END)"
# a flow is part of a behavioural alert when the alert of its window names its source and service (either direction)
BEHAVIOURAL_SQL = ("EXISTS (SELECT 1 FROM behavior_alerts b WHERE b.capture_id = d.capture_id AND "
                   "((b.src_ip = d.src_ip AND (b.dst_port IS NULL OR b.dst_port = d.dst_port)) OR "
                   "(b.src_ip = d.dst_ip AND (b.dst_port IS NULL OR b.dst_port = d.src_port))))")
ACTIVE_SIM_STATUSES = ("requested", "running", "processing")


def app_ports(cfg=None) -> dict[str, list[int]]:
    return {a: [int(p) for p in ports] for a, ports in (cfg or load_config())["unknown_eval"]["applications"].items()}


def monitoring_feed(after_id: int = 0, limit: int = 300, predicted_class: str | None = None, src_ip: str | None = None,
                    app: str | None = None, status: str | None = None, mechanism: str | None = None,
                    origin: str | None = None, cfg=None) -> list[dict[str, Any]]:
    """Newest classified flows of captured windows (id > after_id), with status, mechanism and origin."""
    where, params = [LIVE, "d.id > ?"], [int(after_id)]
    if predicted_class:
        where.append("d.predicted_class = ?")
        params.append(predicted_class)
    if src_ip:
        where.append("d.src_ip = ?")
        params.append(src_ip)
    if app:
        ports = app_ports(cfg).get(app)
        if not ports:
            return []
        marks = ",".join("?" * len(ports))
        where.append(f"(d.dst_port IN ({marks}) OR d.src_port IN ({marks}))")
        params += ports * 2
    if status in ("benign", "attack", "unknown"):
        where.append(f"{STATUS_SQL} = ?")
        params.append(status)
    if mechanism in ("ml", "behavioural", "both", "none"):
        ml, beh = f"{STATUS_SQL} = 'attack'", BEHAVIOURAL_SQL
        where.append({"ml": f"{ml} AND NOT {beh}", "behavioural": f"NOT ({ml}) AND {beh}",
                      "both": f"{ml} AND {beh}", "none": f"NOT ({ml}) AND NOT {beh}"}[mechanism])
    if origin == "simulation":
        where.append("d.sim_run_id IS NOT NULL")
    elif origin == "observed":
        where.append("d.sim_run_id IS NULL")
    sql = (f"SELECT d.id, d.capture_id, d.timestamp, d.detected_at, d.src_ip, d.src_port, d.dst_ip, d.dst_port, "
           f"d.protocol, d.predicted_class, d.confidence, d.is_malicious, {STATUS_SQL} AS status, d.unknown_reason, "
           f"d.sim_run_id, d.capture_file, d.model, {BEHAVIOURAL_SQL} AS behavioural "
           f"FROM detections d WHERE {' AND '.join(where)} ORDER BY d.id DESC LIMIT ?")
    return _q(sql, (*params, int(limit)), cfg)


def monitoring_overview(windows: int = 60, cfg=None) -> dict[str, Any]:
    """Counters, per-window aggregates and distributions of the latest capture windows, in one read."""
    cfg = cfg or load_config()
    with db.connect(db.db_path(cfg)) as c:
        one = lambda sql, p=(): c.execute(sql, p).fetchone()[0]
        totals = c.execute(
            f"SELECT COUNT(*), SUM({STATUS_SQL} = 'benign'), SUM({STATUS_SQL} = 'attack'), SUM({STATUS_SQL} = 'unknown'), "
            f"SUM(d.sim_run_id IS NOT NULL) FROM detections d WHERE {LIVE}").fetchone()
        win = db.query_df(c, f"""
            SELECT c.id, c.pcap_file, c.interface, c.started_at, c.ended_at, c.duration_s, c.packets, c.bytes, c.status,
                   c.csv_file, c.flows, c.conversion_s, c.prediction_ms, c.pipeline_s, c.next_window_s, c.error,
                   COALESCE(SUM({STATUS_SQL} = 'benign'), 0) benign, COALESCE(SUM({STATUS_SQL} = 'attack'), 0) malicious,
                   COALESCE(SUM({STATUS_SQL} = 'unknown'), 0) unknown, COALESCE(SUM(d.sim_run_id IS NOT NULL), 0) lab_flows,
                   COALESCE(SUM({STATUS_SQL} = 'benign' AND {BEHAVIOURAL_SQL}), 0) suspicious,
                   (SELECT COUNT(*) FROM behavior_alerts b WHERE b.capture_id = c.id) alerts
            FROM (SELECT * FROM captures ORDER BY id DESC LIMIT ?) c
            LEFT JOIN detections d ON d.capture_id = c.id AND d.simulated = 0
            GROUP BY c.id ORDER BY c.id DESC""", (int(windows),))
        first = int(win["id"].min()) if len(win) else 0
        classes = db.query_df(c, f"SELECT d.predicted_class, {STATUS_SQL} status, COUNT(*) n FROM detections d "
                                 f"WHERE {LIVE} AND d.capture_id >= ? GROUP BY 1, 2 ORDER BY n DESC", (first,))
        sources = db.query_df(c, f"SELECT d.src_ip, COUNT(*) flows, SUM({STATUS_SQL} = 'attack') malicious, "
                                 f"SUM({STATUS_SQL} = 'unknown') unknown, MAX(d.sim_run_id) sim_run_id "
                                 f"FROM detections d WHERE {LIVE} AND d.capture_id >= ? "
                                 f"GROUP BY 1 ORDER BY flows DESC LIMIT 15", (first,))
        alerts = db.query_df(c, "SELECT id, capture_id, detected_at, alert_type, severity, src_ip, dst_ip, dst_port, "
                                "flows, rate_per_s, window_s, ml_malicious_flows, sim_run_id FROM behavior_alerts "
                                "WHERE capture_id >= ? ORDER BY id DESC LIMIT 500", (first,))
        lat = db.query_df(c, "SELECT AVG(pipeline_s) mean_s, MAX(pipeline_s) max_s FROM "
                             "(SELECT pipeline_s FROM captures WHERE status = 'classified' ORDER BY id DESC LIMIT 20)")
        summary = {
            "total_flows": int(totals[0] or 0), "benign_flows": int(totals[1] or 0),
            "malicious_flows": int(totals[2] or 0), "unknown_flows": int(totals[3] or 0),
            "lab_simulation_flows": int(totals[4] or 0),
            "behavior_alerts": one("SELECT COUNT(*) FROM behavior_alerts"),
            "active_simulations": one(f"SELECT COUNT(*) FROM simulation_runs WHERE status IN "
                                      f"({','.join('?' * len(ACTIVE_SIM_STATUSES))})", ACTIVE_SIM_STATUSES),
            "active_decoys": one("SELECT COUNT(*) FROM decoys WHERE status IN ('deploying', 'active')"),
            "capture_windows": one("SELECT COUNT(*) FROM captures"),
            "pipeline_mean_s": float(lat["mean_s"].iloc[0]) if len(lat) and pd.notna(lat["mean_s"].iloc[0]) else None,
            "pipeline_max_s": float(lat["max_s"].iloc[0]) if len(lat) and pd.notna(lat["max_s"].iloc[0]) else None,
        }
    return {"summary": summary, "windows": _records(win), "classes": _records(classes),
            "sources": _records(sources), "alerts": _records(alerts), "app_ports": app_ports(cfg)}


RUN_COUNTS = ("requests", "connections", "packets", "flows", "detections", "attacks", "unknown", "alerts",
              "capture_owned", "capture_pid")


def _decode_runs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for r in rows:
        for k in ("params", "stages", "capture_ids", "cleanup"):
            r[k] = json.loads(r[k]) if r.get(k) else None
        for k in RUN_COUNTS:          # pandas turns integer columns with NULLs into floats
            if r.get(k) is not None:
                r[k] = int(r[k])
    return rows


def simulation_runs(limit: int = 20, cfg=None) -> list[dict[str, Any]]:
    return _decode_runs(_q("SELECT * FROM simulation_runs ORDER BY created_at DESC LIMIT ?", (int(limit),), cfg))


def simulation_run(run_id: str, cfg=None) -> dict[str, Any] | None:
    rows = _decode_runs(_q("SELECT * FROM simulation_runs WHERE run_id = ?", (run_id,), cfg))
    return rows[0] if rows else None


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
