import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Security Overview")


@st.fragment(run_every="5s" if st.session_state.get("auto_refresh") else None)
def body():
    m, mode = api.metrics()
    ui.mode_banner(mode)
    if not m:
        ui.empty("No data available.")
        return
    k8s, _ = api.k8s_status()
    nodes = (k8s or {}).get("nodes") or []
    cluster = "Ready" if k8s and k8s.get("connected") and nodes and all(n["ready"] == "True" for n in nodes) else \
        ("Unreachable" if not (k8s or {}).get("connected") else "Not ready")

    ui.card_row([
        ui.card("Captured / replayed flows", ui.fmt_int(m["total_flows"]),
                " · ".join(f"{ui.SOURCE_LABELS.get(k, k).split(' (')[0]}: {v:,}" for k, v in m["flows_by_source"].items())),
        ui.card("Benign flows", ui.fmt_int(m["benign_flows"])),
        ui.card("Malicious flows", ui.fmt_int(m["malicious_flows"]), "per-flow ML predictions"),
        ui.card("Active threats", ui.fmt_int(m["active_threats"]), "live sources with confident detections or bursts, 15 min"),
    ])
    st.write("")
    model = m.get("model") or {}
    ui.card_row([
        ui.card("Active decoys", ui.fmt_int(m["active_decoys"])),
        ui.card("Decoy interactions", ui.fmt_int(m["total_interactions"]), f"{ui.fmt_int(m['decisions'])} MAPE-K decisions"),
        ui.card("Model accuracy", ui.fmt_pct(model.get("accuracy")),
                f"{model.get('name')} · macro F1 {model.get('f1_macro', 0):.3f} (offline test set)"),
        ui.card("Cluster status", cluster, (nodes[0]["name"] + " · " + nodes[0]["version"]) if nodes else (k8s or {}).get("error", "")[:60]),
    ])
    st.write("")

    stats, _ = api.detection_stats()
    by = ui.df((stats or {}).get("by_class"))
    c1, c2 = st.columns([1, 1.3])
    with c1:
        if by.empty:
            ui.empty("No detections yet.")
        else:
            agg = by.groupby(["source", "is_malicious"])["n"].sum().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
            labels = [ui.SOURCE_LABELS.get(s, s) for s in agg.index]
            fig = go.Figure([
                go.Bar(name="✓ Benign", y=labels, x=agg[0], orientation="h", marker_color=ui.STATUS["good"],
                       marker_line=dict(color=ui.SURFACE, width=2), hovertemplate="%{y}<br>Benign: %{x:,}<extra></extra>"),
                go.Bar(name="✕ Malicious", y=labels, x=agg[1], orientation="h", marker_color=ui.STATUS["critical"],
                       marker_line=dict(color=ui.SURFACE, width=2), hovertemplate="%{y}<br>Malicious: %{x:,}<extra></extra>"),
            ])
            fig.update_layout(barmode="stack", title="Benign vs malicious flows by data source")
            st.plotly_chart(ui.style(fig, 300), width="stretch")
    with c2:
        mal = by[by["is_malicious"] == 1].groupby("predicted_class")["n"].sum().sort_values() if not by.empty else pd.Series()
        if mal.empty:
            ui.empty("No malicious predictions yet.")
        else:
            fig = go.Figure(go.Bar(y=mal.index, x=mal.values, orientation="h", marker_color=ui.SERIES[0],
                                   text=[f"{v:,}" for v in mal.values], textposition="outside",
                                   textfont=dict(color=ui.INK2), cliponaxis=False,
                                   hovertemplate="%{y}: %{x:,} flows<extra></extra>"))
            fig.update_layout(title="Attack category distribution (ML predictions, all sources)")
            st.plotly_chart(ui.style(fig, 300, legend=False), width="stretch")

    c3, c4 = st.columns([1.3, 1])
    with c3:
        st.subheader("Recent malicious detections")
        d, _ = api.detections(limit=12, malicious=True)
        ui.detections_table(ui.df(d), height=320)
    with c4:
        st.subheader("Recent deception decisions")
        dec = ui.df(api.decisions(limit=12)[0])
        if dec.empty:
            ui.empty("No MAPE-K decisions yet.")
        else:
            st.dataframe(pd.DataFrame({
                "Time": dec["created_at"].str.slice(11, 19),
                "Trigger": dec["trigger"] + dec["simulated"].map({1: " (SIMULATED)", 0: ""}),
                "Action": dec["action"], "Decoy": dec["decoy_profile"].fillna(""),
                "Result": dec["result"], "Why": dec["reason"],
            }), hide_index=True, width="stretch", height=320)


body()
