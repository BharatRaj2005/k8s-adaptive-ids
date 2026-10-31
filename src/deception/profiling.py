"""Summaries of decoy interactions per source.

Only request metadata stored in `interactions` is used (time, decoy, method, path,
status, interaction type, body size); request bodies are never stored. Each
(source, decoy) pair gets a category, with thresholds in `deception.profiling`:

  enumerating      many distinct paths, mostly unknown ones (scan of the decoy)
  repeated_access  the same few resources requested again and again
  exploring        several requests across known pages
  single_probe     fewer than `min_requests` requests
"""
from __future__ import annotations

from typing import Any

import pandas as pd

CATEGORIES = ("enumerating", "repeated_access", "exploring", "single_probe")


def categorize(n: int, unique_paths: int, unknown_share: float, top_path_count: int, p: dict[str, Any]) -> str:
    if n < p["min_requests"]:
        return "single_probe"
    if unique_paths >= p["enumerate_min_paths"] and unknown_share >= p["enumerate_min_unknown_share"]:
        return "enumerating"
    if unique_paths <= p["repeat_max_paths"] and top_path_count >= p["repeat_min_count"]:
        return "repeated_access"
    return "exploring"


def summarize(interactions: pd.DataFrame, p: dict[str, Any]) -> list[dict[str, Any]]:
    """One summary per (src_ip, decoy_name), most recent activity first."""
    if interactions.empty:
        return []
    df = interactions.copy()
    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce", format="mixed")
    out = []
    for (src, decoy), g in df.groupby(["src_ip", "decoy_name"], dropna=False):
        n = len(g)
        paths = g["path"].fillna("")
        top = paths.value_counts()
        unknown = float((g["interaction_type"] == "unknown_path").mean())
        span = (g["ts"].max() - g["ts"].min()).total_seconds() if g["ts"].notna().any() else None
        out.append({
            "src_ip": src, "decoy_name": decoy,
            "decoy_profile": g["decoy_profile"].dropna().iloc[0] if g["decoy_profile"].notna().any() else None,
            "requests": int(n), "unique_paths": int(top.size),
            "unknown_path_share": round(unknown, 3),
            "top_path": top.index[0] if top.size else None, "top_path_count": int(top.iloc[0]) if top.size else 0,
            "methods": g["method"].value_counts().to_dict(),
            "statuses": {str(k): int(v) for k, v in g["status"].value_counts().items()},
            "types": g["interaction_type"].value_counts().to_dict(),
            "data_submissions": int((g["interaction_type"] == "data_submission").sum()),
            "first_seen": g["ts"].min().isoformat() if g["ts"].notna().any() else None,
            "last_seen": g["ts"].max().isoformat() if g["ts"].notna().any() else None,
            "duration_s": round(span, 1) if span is not None else None,
            "requests_per_min": round(n / (span / 60), 2) if span else None,
            "decision_ids": sorted({int(x) for x in g["decision_id"].dropna()}),
            "category": categorize(n, int(top.size), unknown, int(top.iloc[0]) if top.size else 0, p),
        })
    return sorted(out, key=lambda r: r["last_seen"] or "", reverse=True)
