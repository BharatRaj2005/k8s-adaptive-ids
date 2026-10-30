import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Attack Classification")
st.caption("Multi-class predictions of the active per-flow model across all stored detections (simulated events excluded).")


@st.fragment(run_every="5s" if st.session_state.get("auto_refresh") else None)
def body():
    stats, mode = api.detection_stats()
    ui.mode_banner(mode)
    by = ui.df((stats or {}).get("by_class"))
    if by.empty:
        ui.empty("No detections stored yet. Replay a dataset file or start a capture.")
        return
    src = st.radio("Data source", ["All", *sorted(by["source"].unique())], horizontal=True,
                   format_func=lambda s: ui.SOURCE_LABELS.get(s, s))
    if src != "All":
        by = by[by["source"] == src]

    per_class = by.groupby("predicted_class").agg(n=("n", "sum")).sort_values("n")
    mean_conf = (by.assign(w=by["n"] * by["mean_conf"]).groupby("predicted_class")["w"].sum() / per_class["n"]).reindex(per_class.index)
    c1, c2 = st.columns(2)
    with c1:
        fig = go.Figure(go.Bar(y=per_class.index, x=per_class["n"], orientation="h", marker_color=ui.SERIES[0],
                               text=[f"{v:,}" for v in per_class["n"]], textposition="outside", cliponaxis=False,
                               textfont=dict(color=ui.INK2), hovertemplate="%{y}: %{x:,} flows<extra></extra>"))
        fig.update_layout(title="Multi-class prediction distribution")
        fig.update_xaxes(type="log", title="flows (log scale)",
                         range=[0, np.log10(max(per_class["n"].max(), 10) * 4)])  # room for value labels
        st.plotly_chart(ui.style(fig, 380, legend=False), width="stretch")
    with c2:
        fig = go.Figure(go.Bar(y=mean_conf.index, x=mean_conf.values, orientation="h", marker_color=ui.SERIES[0],
                               text=[f"{v:.2f}" for v in mean_conf.values], textposition="outside", cliponaxis=False,
                               textfont=dict(color=ui.INK2), hovertemplate="%{y}: mean confidence %{x:.3f}<extra></extra>"))
        fig.update_layout(title="Mean prediction confidence per class")
        fig.update_xaxes(range=[0, 1.1])
        st.plotly_chart(ui.style(fig, 380, legend=False), width="stretch")

    rows, _ = api.detections(limit=5000, malicious=True, source=None if src == "All" else src)
    d = ui.df(rows)
    if not d.empty:
        d["minute"] = d["detected_at"].str.slice(0, 16).str.replace("T", " ")
        heat = d.groupby(["predicted_class", "minute"]).size().unstack(fill_value=0)
        # log color scale so small bursts stay visible next to large dataset replays; hover shows true counts
        ticks = [t for t in (1, 10, 100, 1000, 10000) if t <= max(heat.values.max(), 1)]
        fig = go.Figure(go.Heatmap(z=np.log10(1 + heat.values), x=heat.columns, y=heat.index, customdata=heat.values,
                                   colorscale=ui.BLUE_RAMP, xgap=2, ygap=2,
                                   hovertemplate="%{y}<br>%{x}: %{customdata} flows<extra></extra>",
                                   colorbar=dict(title=dict(text="flows (log)", font=dict(color=ui.INK2)),
                                                 tickvals=[np.log10(1 + t) for t in ticks], ticktext=[f"{t:,}" for t in ticks],
                                                 tickfont=dict(color=ui.MUTED))))
        fig.update_layout(title="Per-class detection history (attack frequency per minute, latest 5000 malicious flows)")
        fig.update_xaxes(type="category")
        st.plotly_chart(ui.style(fig, 360, legend=False), width="stretch")

    conf = ui.df((stats or {}).get("confidence"))
    pick = st.selectbox("Confidence distribution for class", sorted(by["predicted_class"].unique()))
    cc = conf[conf["predicted_class"] == pick].sort_values("bucket") if not conf.empty else conf
    if not cc.empty:
        fig = go.Figure(go.Bar(x=cc["bucket"].map(lambda b: "1.0" if b >= 1 else f"{b:.1f}–{b + 0.1:.1f}"), y=cc["n"],
                               marker_color=ui.SERIES[0], hovertemplate="confidence %{x}: %{y:,} flows<extra></extra>"))
        fig.update_layout(title=f"Prediction confidence: {pick}")
        st.plotly_chart(ui.style(fig, 260, legend=False), width="stretch")

    st.subheader("Detailed detection records")
    pick2 = st.selectbox("Filter records by class", ["All malicious", *sorted(by["predicted_class"].unique())])
    recs, _ = api.detections(limit=1000, source=None if src == "All" else src,
                             predicted_class=None if pick2 == "All malicious" else pick2,
                             malicious=True if pick2 == "All malicious" else None)
    ui.detections_table(ui.df(recs), height=360)


body()
