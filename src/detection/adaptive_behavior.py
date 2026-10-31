"""Learned behavioural thresholds on top of the fixed flow-burst detector.

The fixed detector (behavior.py) reports a source that opens >= `min_flows` flows to
one service in a window. This module keeps it unchanged and adds two checks whose
thresholds are learned per service from benign traffic:

  adaptive_rate  flows per second of (source, service) in this window
  slow_scan      flows of (source, destination, service) summed over the last `horizon_s` seconds

threshold = median + k * max(1.4826 * MAD, min_scale), computed from the history of
values of that service, bounded below by a floor and above by the fixed detector's
level. Because of the upper bound the learned checks are never less sensitive than
the fixed detector. Only values that did not raise an alert enter the history, and
until a service has `warmup` values the fixed level is used.
"""
from __future__ import annotations

import json
from typing import Any

import numpy as np
import pandas as pd

from src.detection.behavior import BURST_COLUMNS, flow_bursts

ALERT_COLUMNS = [*BURST_COLUMNS, "alert_type", "severity", "threshold", "baseline", "details"]
STATE_KEY = "behavior_state_v1"


def learned_threshold(history: list[float], k: float, min_scale: float, floor: float, ceiling: float,
                      warmup: int) -> tuple[float, float | None]:
    """(threshold, median of history or None during warm-up)."""
    if len(history) < warmup:
        return ceiling, None
    a = np.asarray(history, dtype=float)
    med = float(np.median(a))
    mad = float(np.median(np.abs(a - med)))
    thr = med + k * max(1.4826 * mad, min_scale)
    return float(min(max(thr, floor), ceiling)), med


def _push(hist: list[float], value: float, size: int) -> None:
    hist.append(round(float(value), 4))
    del hist[:-size]


class AdaptiveBehavior:
    """Per-window analysis with a JSON-serialisable state (stored in the kv table)."""

    def __init__(self, cfg: dict[str, Any], state: dict[str, Any] | None = None):
        self.cfg = cfg
        self.b = cfg["behavior"]
        self.a = self.b["adaptive"]
        self.state = state or {"rate": {}, "horizon": {}, "recent": [], "windows": 0}

    def analyze(self, pred: pd.DataFrame, window_s: float | None, window_end: float) -> pd.DataFrame:
        """Alerts for one window; `window_end` is a POSIX timestamp."""
        fixed = flow_bursts(pred, window_s, self.cfg)
        alerts = [{**r, "alert_type": "flow_burst", "severity": "high", "threshold": float(self.b["min_flows"]),
                   "baseline": None, "details": json.dumps({"detector": "fixed"})}
                  for r in fixed.to_dict(orient="records")]
        self.state["windows"] += 1
        if not self.a.get("enabled", True) or pred.empty or not window_s or window_s <= 0:
            return pd.DataFrame(alerts, columns=ALERT_COLUMNS)

        df = pred[pred["src_ip"].notna() & pred["dst_ip"].notna() & pred["dst_port"].notna()]
        df = df[df["protocol"].isin(self.b["protocols"]) & ~df["src_ip"].isin(self.b.get("ignore_sources", []))]
        fixed_keys = {(r["src_ip"], int(r["dst_port"])) for r in alerts}
        a, size = self.a, self.a["history_size"]
        rate_ceiling = max(self.b["min_rate_per_s"], self.b["min_flows"] / window_s)
        horizon = float(a["horizon_s"])
        recent = [r for r in self.state["recent"] if r[0] > window_end - horizon and len(r) == 5]
        # horizon sums are only meaningful once a full horizon of windows has been seen
        first = self.state.setdefault("first_end", window_end)
        horizon_full = window_end - first >= horizon

        counts = df.groupby(["src_ip", "dst_ip", "dst_port", "protocol"]).agg(
            flows=("src_ip", "size"), ml_malicious=("is_malicious", "sum"))
        learn_rate, learn_h = [], []
        for (src, dst, port, proto), row in counts.iterrows():
            svc = f"{int(proto)}:{int(port)}"
            n = int(row["flows"])
            rate = n / window_s
            recent.append([window_end, src, dst, svc, n])
            in_h = sum(r[4] for r in recent if r[1] == src and r[2] == dst and r[3] == svc)
            base = {"src_ip": src, "dst_ip": dst, "dst_port": int(port), "protocol": int(proto), "flows": n,
                    "rate_per_s": round(rate, 3), "ml_malicious_flows": int(row["ml_malicious"]),
                    "ml_classes": json.dumps({}), "window_s": float(window_s)}
            if (src, int(port)) in fixed_keys:
                continue
            thr_r, med_r = learned_threshold(self.state["rate"].get(svc, []), a["k"], a["rate_min_scale"],
                                             a["rate_floor_per_s"], rate_ceiling, a["warmup"])
            thr_h, med_h = learned_threshold(self.state["horizon"].get(svc, []), a["k"], a["horizon_min_scale"],
                                             a["horizon_floor_flows"], a["horizon_max_flows"], a["warmup"])
            if n >= a["min_flows"] and rate >= thr_r:
                alerts.append({**base, "alert_type": "adaptive_rate", "severity": "medium",
                               "threshold": round(thr_r * window_s, 2), "baseline": med_r,
                               "details": json.dumps({"detector": "adaptive", "rate_threshold_per_s": round(thr_r, 3),
                                                      "basis": "learned" if med_r is not None else "warm-up"})})
            elif horizon_full and in_h >= thr_h:
                alerts.append({**base, "alert_type": "slow_scan", "severity": "medium", "threshold": round(thr_h, 2),
                               "baseline": med_h,
                               "details": json.dumps({"detector": "adaptive", "horizon_s": horizon,
                                                      "horizon_flows": int(in_h),
                                                      "basis": "learned" if med_h is not None else "warm-up"})})
            else:
                learn_rate.append((svc, min(rate, thr_r)))
                if horizon_full:
                    learn_h.append((svc, min(in_h, thr_h)))
        for svc, v in learn_rate:
            _push(self.state["rate"].setdefault(svc, []), v, size)
        for svc, v in learn_h:
            _push(self.state["horizon"].setdefault(svc, []), v, size)
        self.state["recent"] = recent[-a["recent_max"]:]
        return pd.DataFrame(alerts, columns=ALERT_COLUMNS)

    def thresholds(self) -> dict[str, Any]:
        """Current learned thresholds per service (for the API/dashboard)."""
        a = self.a
        out = {}
        for svc in sorted(set(self.state["rate"]) | set(self.state["horizon"])):
            r = self.state["rate"].get(svc, [])
            h = self.state["horizon"].get(svc, [])
            out[svc] = {"rate_observations": len(r), "horizon_observations": len(h),
                        "rate_median": float(np.median(r)) if r else None,
                        "horizon_median": float(np.median(h)) if h else None,
                        "horizon_threshold": learned_threshold(h, a["k"], a["horizon_min_scale"],
                                                               a["horizon_floor_flows"], a["horizon_max_flows"],
                                                               a["warmup"])[0]}
        return out
