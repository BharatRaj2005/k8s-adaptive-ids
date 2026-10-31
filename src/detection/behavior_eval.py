"""Replay recorded capture windows through the fixed and the adaptive behavioural detector.

    python -m src.detection.behavior_eval   # sessions from config behavior_eval.sessions and
                                            # data/lab/behavior_sessions/*.json (scripts/behaviour_scenarios.py)

Ground truth comes from the lab: each session lists the pod IPs of the traffic
generator Jobs that acted as attackers (recon and decoy-probe Jobs) with the time
span they ran. A (window, source) pair is an *attack pair* when an attacker
source sent TCP flows in that window, and a *benign pair* for every other source.
Windows are replayed in time order with a fresh adaptive state, so the learned
thresholds only use windows that precede the one being scored.

Metrics per detector: pair-level true/false positive rates, precision, alerts
per window, and per scenario the windows detected and the detection delay
(end of the first alerting window minus the scenario start).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd

from src.detection.adaptive_behavior import AdaptiveBehavior
from src.detection.behavior import flow_bursts
from src.preprocessing.schema import DST_IP, DST_PORT, PROTOCOL, SRC_IP, read_flow_csv
from src.utils import db
from src.utils.config import get_path, load_config


def _ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def load_windows(start: str, end: str, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute(
            "SELECT csv_file, started_at, ended_at, duration_s FROM captures WHERE status = 'classified' "
            "AND csv_file IS NOT NULL AND started_at >= ? AND started_at < ? ORDER BY started_at", (start, end))]
    out, flows_dir = [], get_path("flows_dir", cfg)
    for r in rows:
        path = flows_dir / r["csv_file"]
        if not path.is_file():
            continue
        f = read_flow_csv(path)
        pred = pd.DataFrame({"src_ip": f[SRC_IP], "dst_ip": f[DST_IP], "dst_port": f[DST_PORT],
                             "protocol": f[PROTOCOL], "is_malicious": False, "predicted_class": "n/a"})
        out.append({**r, "start": _ts(r["started_at"]), "end": _ts(r["ended_at"]), "pred": pred})
    return out


def score(session: dict[str, Any], windows: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    attackers = {s["ip"]: s for s in session["scenarios"]}
    protos = cfg["behavior"]["protocols"]
    detectors = {"fixed": None, "adaptive": AdaptiveBehavior(cfg)}
    res: dict[str, Any] = {}
    for name, det in detectors.items():
        tp = fp = fn = tn = 0
        alerts_per_window = []
        first_alert: dict[str, float] = {}
        detected_windows: dict[str, int] = {ip: 0 for ip in attackers}
        active_windows: dict[str, int] = {ip: 0 for ip in attackers}
        types: dict[str, int] = {}
        false_sources: dict[str, int] = {}
        for w in windows:
            pred = w["pred"]
            alerts = flow_bursts(pred, w["duration_s"], cfg) if det is None else det.analyze(pred, w["duration_s"], w["end"])
            alerts_per_window.append(len(alerts))
            if det is not None:
                for t in alerts["alert_type"]:
                    types[t] = types.get(t, 0) + 1
            flagged = set(alerts["src_ip"])
            sources = set(pred.loc[pred["protocol"].isin(protos), "src_ip"].dropna())
            for src in sources:
                attack = src in attackers
                hit = src in flagged
                if attack:
                    active_windows[src] += 1
                    detected_windows[src] += hit
                    if hit and src not in first_alert:
                        first_alert[src] = w["end"]
                tp += attack and hit
                fn += attack and not hit
                fp += (not attack) and hit
                tn += (not attack) and not hit
                if hit and not attack:
                    false_sources[src] = false_sources.get(src, 0) + 1
        scen = {}
        for ip, s in attackers.items():
            # scenario start: given, else the start of the first window with flows from the attacker
            # (the true start lies inside that window, so the delay is overestimated by < 1 window)
            seen = [w["start"] for w in windows if (w["pred"]["src_ip"] == ip).any()]
            start = _ts(s["start"]) if s.get("start") else (min(seen) if seen else float("nan"))
            scen[s["name"]] = {"ip": ip, "kind": s.get("kind", "recon"), "rate_per_s": s.get("rate_per_s"),
                               "active_windows": active_windows[ip], "detected_windows": detected_windows[ip],
                               "window_recall": detected_windows[ip] / active_windows[ip] if active_windows[ip] else None,
                               "detected": ip in first_alert,
                               "delay_s": round(first_alert[ip] - start, 1) if ip in first_alert else None}
        res[name] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "tpr": tp / (tp + fn) if tp + fn else None, "fpr": fp / (fp + tn) if fp + tn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "alerts_per_window_mean": float(np.mean(alerts_per_window)) if alerts_per_window else 0.0,
            "alerts_per_window_max": int(max(alerts_per_window, default=0)),
            "false_alert_sources": false_sources, "alert_types": types, "scenarios": scen,
        }
    return {"name": session["name"], "windows": len(windows), "from": session["from"], "to": session["to"],
            "results": res}


def main() -> None:
    cfg = load_config()
    out = {"generated_at": datetime.now().astimezone().isoformat(), "config": cfg["behavior"], "sessions": []}
    recorded = sorted((get_path("processed_dir", cfg).parent / "lab" / "behavior_sessions").glob("*.json"))
    sessions = [*cfg["behavior_eval"]["sessions"], *(json.loads(p.read_text()) for p in recorded)]
    for s in sessions:
        windows = load_windows(s["from"], s["to"], cfg)
        out["sessions"].append(score(s, windows, cfg))
        for det, r in out["sessions"][-1]["results"].items():
            print(f"{s['name']:14s} {det:9s} tpr={r['tpr']} fpr={r['fpr']} prec={r['precision']} "
                  f"alerts/win={r['alerts_per_window_mean']:.2f} false={r['false_alert_sources']}")
            for n, sc in r["scenarios"].items():
                print(f"    {n:22s} windows {sc['detected_windows']}/{sc['active_windows']} delay={sc['delay_s']}")
    path = get_path("reports_dir", cfg) / "behavioural_detection.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    path.with_suffix(".md").write_text(render_markdown(out))
    print("wrote", path, "and", path.with_suffix(".md"))


def _f(v, pct=False):
    if v is None:
        return "–"
    return f"{100 * v:.1f}%" if pct else (f"{v:.2f}" if isinstance(v, float) else str(v))


def render_markdown(out: dict[str, Any]) -> str:
    b = out["config"]
    a = b["adaptive"]
    L = ["# Behavioural detection: fixed vs adaptive thresholds", "",
         f"Generated {out['generated_at'][:19]} by `python -m src.detection.behavior_eval` from recorded capture "
         "windows (replayed in time order; nothing is simulated).", "",
         "## Detectors", "",
         f"* **Fixed** (`src/detection/behavior.py`, unchanged): alert when one source opens ≥ {b['min_flows']} TCP "
         f"flows to one destination service in a window at ≥ {b['min_rate_per_s']} flows/s.",
         "* **Adaptive** (`src/detection/adaptive_behavior.py`): the fixed rule plus two learned thresholds per "
         "service, `median + k·max(1.4826·MAD, min_scale)` of past non-alerting values, bounded by a floor and by "
         "the fixed rule's level:",
         f"  * `adaptive_rate`: flows/s of (source, destination, service) in the window (k = {a['k']}, floor "
         f"{a['rate_floor_per_s']}/s, at least {a['min_flows']} flows);",
         f"  * `slow_scan`: flows of (source, destination, service) over the last {a['horizon_s']:.0f} s (floor "
         f"{a['horizon_floor_flows']}, cap {a['horizon_max_flows']}).",
         f"  * Learned values are used after {a['warmup']} observations per service. Alerting values are not learned, "
         "and learned values are clipped at the current threshold.",
         "  * Adaptive alerts are `medium` severity. The controller acts on them only after "
         "`deception.thresholds.behavior_repeat_count` alert windows, or when the ML classifier flags the same source.",
         "", "## Ground truth and metrics", "",
         "Each session lists the lab Job pods that acted as attackers. A (window, source) pair is an attack pair when "
         "an attacker pod sent TCP flows in that window; every other source in that window is a benign pair.", "",
         "* **TPR / FPR / precision** are computed over pairs.",
         "* **Detection delay** is the end of the first alerting window minus the scenario start: the first request "
         "in the generator log, or else the start of the first window containing the attacker, which overestimates "
         "the delay by less than one window.", ""]
    for s in out["sessions"]:
        L += [f"## {s['name']} ({s['windows']} windows, {s['from'][:19]} – {s['to'][:19]})", "",
              "| Detector | TPR | FPR | Precision | Alerts / window (mean / max) | False-alert sources |", "|---|---|---|---|---|---|"]
        for det, r in s["results"].items():
            fa = ", ".join(f"{k} ×{v}" for k, v in r["false_alert_sources"].items()) or "none"
            L.append(f"| {det} | {_f(r['tpr'], True)} | {_f(r['fpr'], True)} | {_f(r['precision'], True)} | "
                     f"{r['alerts_per_window_mean']:.2f} / {r['alerts_per_window_max']} | {fa} |")
        fx, ad = s["results"]["fixed"]["scenarios"], s["results"]["adaptive"]["scenarios"]
        L += ["", "| Scenario | Requests/s per pod | Windows with attacker | Detected (fixed) | Detected (adaptive) | "
              "Delay fixed (s) | Delay adaptive (s) |", "|---|---|---|---|---|---|---|"]
        for n in fx:
            L.append(f"| {n} | {_f(fx[n]['rate_per_s'])} | {fx[n]['active_windows']} | "
                     f"{fx[n]['detected_windows']} | {ad[n]['detected_windows']} | {_f(fx[n]['delay_s'])} | "
                     f"{_f(ad[n]['delay_s'])} |")
        types = s["results"]["adaptive"]["alert_types"]
        L += ["", f"Adaptive alert types: {types or 'none'}.", ""]
    L += ["## Limitations", "",
          "* Only flow metadata is used. HTTP paths and status codes are not visible in CICFlowMeter records, so "
          "path-enumeration features are not available.",
          "* A source whose request rate is close to that of normal clients of the same service cannot be separated "
          "by volume alone. The per-flow ML classifier is the complementary signal there.",
          "* Thresholds are learned from the traffic that is observed. The fixed-level cap bounds how far a learned "
          "threshold can move, but the learned part assumes the warm-up period is benign.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    main()
