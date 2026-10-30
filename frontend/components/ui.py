"""Shared look: dark SOC theme tokens, cards, badges and Plotly styling.

Colors are the dark-mode steps of the validated reference palette: categorical
slots 1-3 (validated all-pairs on #1a1a19), the fixed status palette for
benign/malicious state (always paired with an icon and a label), and a
single-hue blue ramp for magnitude.
"""
from __future__ import annotations

import html
from typing import Any, Iterable

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

SURFACE = "#1a1a19"
PAGE = "#0d0d0d"
INK = "#f0efec"
INK2 = "#c3c2b7"
MUTED = "#898781"
GRID = "#2c2c2a"
AXIS = "#383835"
BORDER = "rgba(255,255,255,0.10)"
SERIES = ["#3987e5", "#d95926", "#199e70"]  # blue, orange, aqua
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
# Capped at step 400 so white cell labels stay legible on every cell of the dark surface.
BLUE_RAMP = [[0.0, "#1e2733"], [0.35, "#184f95"], [0.7, "#256abf"], [1.0, "#3987e5"]]
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

SOURCE_LABELS = {"pcap": "Live capture (processed PCAP)", "live": "Live capture", "dataset": "Historical dataset replay"}
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "other"}

CSS = f"""
<style>
.block-container {{padding-top: 1.6rem; max-width: 1500px;}}
.ids-card {{background:{SURFACE}; border:1px solid {BORDER}; border-radius:10px; padding:14px 16px; height:100%;}}
.ids-card .lbl {{color:{MUTED}; font-size:0.74rem; letter-spacing:.06em; text-transform:uppercase;}}
.ids-card .val {{color:{INK}; font-size:1.7rem; font-weight:600; line-height:1.25; margin-top:2px;}}
.ids-card .sub {{color:{INK2}; font-size:0.78rem; margin-top:2px;}}
.ids-badge {{display:inline-block; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600;
            border:1px solid {BORDER}; color:{INK}; background:{SURFACE}; margin-right:6px;}}
.ids-badge .dot {{display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle;}}
.ids-stage {{display:inline-block; padding:6px 14px; margin:0 4px 6px 0; border-radius:8px; border:1px solid {BORDER};
            color:{INK2}; background:{SURFACE}; font-size:0.85rem;}}
.ids-stage.on {{border-color:{SERIES[0]}; color:{INK}; box-shadow: inset 0 0 0 1px {SERIES[0]};}}
.ids-note {{color:{INK2}; font-size:0.82rem;}}
.ids-sim {{color:{STATUS['warning']}; font-weight:700;}}
</style>
"""


def setup_page() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def card(label: str, value: Any, sub: str = "") -> str:
    v = "—" if value is None else value
    return (f'<div class="ids-card"><div class="lbl">{html.escape(label)}</div>'
            f'<div class="val">{html.escape(str(v))}</div><div class="sub">{html.escape(sub)}</div></div>')


def card_row(cards: Iterable[str]) -> None:
    cards = list(cards)
    for col, c in zip(st.columns(len(cards)), cards):
        col.markdown(c, unsafe_allow_html=True)


def badge(text: str, state: str = "good") -> str:
    icon = {"good": "✓ ", "warning": "! ", "serious": "! ", "critical": "✕ ", "neutral": ""}[state]
    color = STATUS.get(state, MUTED)
    return (f'<span class="ids-badge"><span class="dot" style="background:{color}"></span>'
            f'{icon}{html.escape(text)}</span>')


def mode_banner(mode: str) -> None:
    if mode == "offline":
        st.markdown(badge("Backend offline — showing stored records from SQLite (read-only)", "warning"),
                    unsafe_allow_html=True)


def fmt_int(n) -> str:
    return "—" if n is None else f"{int(n):,}"


def fmt_pct(x, digits=1) -> str:
    return "—" if x is None else f"{x * 100:.{digits}f}%"


def style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, margin=dict(l=12, r=12, t=36, b=12),
        font=dict(family=FONT, color=INK2, size=12), title=dict(font=dict(color=INK, size=14), x=0.01),
        showlegend=legend, legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                                       font=dict(color=INK2), bgcolor="rgba(0,0,0,0)"),
        hoverlabel=dict(bgcolor=PAGE, bordercolor=AXIS, font=dict(color=INK, family=FONT)),
        barcornerradius=4, bargap=0.3,
    )
    fig.update_xaxes(gridcolor=GRID, linecolor=AXIS, zerolinecolor=AXIS, tickfont=dict(color=MUTED), title_font=dict(color=INK2))
    fig.update_yaxes(gridcolor=GRID, linecolor=AXIS, zerolinecolor=AXIS, tickfont=dict(color=MUTED), title_font=dict(color=INK2))
    return fig


def empty(msg: str) -> None:
    st.markdown(f'<div class="ids-card"><div class="ids-note">{html.escape(msg)}</div></div>', unsafe_allow_html=True)


def df(rows: list[dict] | None) -> pd.DataFrame:
    return pd.DataFrame(rows or [])


def detections_table(d: pd.DataFrame, height: int = 380) -> None:
    if d.empty:
        empty("No detection records.")
        return
    t = pd.DataFrame({
        "Detected": d["detected_at"].str.slice(0, 19).str.replace("T", " "),
        "Status": d["is_malicious"].map(lambda m: "✕ Malicious" if m else "✓ Benign"),
        "Predicted class": d["predicted_class"], "Confidence": d["confidence"].astype(float),
        "Src IP": d["src_ip"].fillna("unknown"), "Src port": d["src_port"],
        "Dst IP": d["dst_ip"].fillna("unknown"), "Dst port": d["dst_port"],
        "Protocol": d["protocol"].map(lambda p: PROTOCOLS.get(int(p), str(int(p))) if pd.notna(p) else "unknown"),
        "Data source": d["source"].map(SOURCE_LABELS).fillna(d["source"]),
        "Flow start": d["timestamp"].fillna("unknown").astype(str).str.slice(0, 19).str.replace("T", " "),
        "Capture file": d["capture_file"].fillna("unknown"), "Model": d["model"],
    })
    st.dataframe(t, hide_index=True, width="stretch", height=height, column_config={
        "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="%.2f"),
        "Src port": st.column_config.NumberColumn(format="%d"), "Dst port": st.column_config.NumberColumn(format="%d"),
    })
