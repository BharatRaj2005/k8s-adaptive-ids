import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Live Traffic Monitoring")
st.caption("Flows classified by the per-flow model, plus per-source flow bursts from the behavioural detector. "
           "Live capture is processed in windows (≥ one window of delay), not packet by packet.")

class_list = sorted(set(api.classes().values()))

f1, f2, f3, f4, f5 = st.columns([1.4, 1.4, 1, 1, 1])
sources = f1.multiselect("Data source", list(ui.SOURCE_LABELS), default=["pcap", "dataset"],
                         format_func=lambda s: ui.SOURCE_LABELS[s])
cls = f2.selectbox("Attack class", ["All"] + class_list)
src_ip = f3.text_input("Source IP").strip() or None
dst_ip = f4.text_input("Destination IP").strip() or None
status = f5.selectbox("Prediction status", ["All", "Malicious", "Benign"])
limit = st.slider("Rows per source", 100, 5000, 1000, step=100)


@st.fragment(run_every="5s" if st.session_state.get("auto_refresh") else None)
def body():
    frames, mode = [], "live"
    for s in sources:
        rows, mode = api.detections(limit=limit, source=s, predicted_class=None if cls == "All" else cls, src_ip=src_ip,
                                    dst_ip=dst_ip, malicious=None if status == "All" else status == "Malicious")
        frames.append(ui.df(rows))
    ui.mode_banner(mode)
    d = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()

    counts = d["source"].value_counts().to_dict() if not d.empty else {}
    st.markdown(" ".join(ui.badge(f"{ui.SOURCE_LABELS[s]}: {counts.get(s, 0):,} rows shown", "neutral") for s in sources),
                unsafe_allow_html=True)

    if not d.empty:
        t = d.assign(minute=d["detected_at"].str.slice(0, 16).str.replace("T", " "))
        g = t.groupby(["minute", "is_malicious"]).size().unstack(fill_value=0).reindex(columns=[0, 1], fill_value=0)
        fig = go.Figure([
            go.Bar(name="✓ Benign", x=g.index, y=g[0], marker_color=ui.STATUS["good"],
                   marker_line=dict(color=ui.SURFACE, width=2), hovertemplate="%{x}<br>Benign: %{y:,}<extra></extra>"),
            go.Bar(name="✕ Malicious", x=g.index, y=g[1], marker_color=ui.STATUS["critical"],
                   marker_line=dict(color=ui.SURFACE, width=2), hovertemplate="%{x}<br>Malicious: %{y:,}<extra></extra>"),
        ])
        fig.update_layout(barmode="stack", title="Classified flows per minute (time of detection, UTC)")
        fig.update_xaxes(type="category")
        st.plotly_chart(ui.style(fig, 260), width="stretch")

    st.subheader("Recent flows")
    ui.detections_table(d.sort_values("detected_at", ascending=False) if not d.empty else d, height=420)

    st.subheader("Flow bursts (behavioural detector)")
    a = ui.df(api.alerts(200)[0])
    if a.empty:
        ui.empty("No flow bursts recorded.")
    else:
        if src_ip:
            a = a[a["src_ip"] == src_ip]
        st.dataframe(pd.DataFrame({
            "Detected": a["detected_at"].str.slice(0, 19).str.replace("T", " "), "Src IP": a["src_ip"],
            "Dst IP": a["dst_ip"], "Dst port": a["dst_port"], "Flows in window": a["flows"],
            "Rate (flows/s)": a["rate_per_s"], "Window (s)": a["window_s"].round(1),
            "ML-malicious flows": a["ml_malicious_flows"], "Capture": a["capture_file"],
        }), hide_index=True, width="stretch", height=260)


body()
