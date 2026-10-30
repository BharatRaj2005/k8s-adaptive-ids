import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Model Performance")
st.caption("Measured on the held-out temporal test split of the Kubernetes dataset (last 25 % of every capture) "
           "and on traffic recorded in this lab. Values come from models/*/metrics.json.")

perf, mode = api.model_performance()
ui.mode_banner(mode)
if not perf or "test" not in perf:
    ui.empty("No trained model metrics found.")
    st.stop()
registry = perf.get("registry", {})
names = sorted(registry)
name = st.selectbox("Model", names, index=names.index(perf["name"]) if perf.get("name") in names else 0,
                    format_func=lambda n: n + ("  (active)" if n == perf.get("name") else ""))
m = perf if name == perf.get("name") else api.model_metrics(name)[0]
t, lat, h = m["test"], m["latency"], m.get("benign_holdout", {})

ui.card_row([
    ui.card("Accuracy", f"{t['accuracy']:.4f}", f"{t['test_rows']:,} test flows"),
    ui.card("Macro precision", f"{t['precision_macro']:.4f}"),
    ui.card("Macro recall", f"{t['recall_macro']:.4f}"),
    ui.card("Macro F1", f"{t['f1_macro']:.4f}", f"{len(t['labels'])} classes"),
    ui.card("Weighted F1", f"{t['f1_weighted']:.4f}"),
])
st.write("")
ui.card_row([
    ui.card("Single-flow latency", f"{lat['single_flow_median_ms']:.1f} ms", f"median; p95 {lat['single_flow_p95_ms']:.1f} ms"),
    ui.card("Batch throughput", f"{lat['batch_per_flow_us']:.0f} µs/flow", f"{lat['batch_rows']:,} flows in {lat['batch_total_ms']:.0f} ms"),
    ui.card("Attack detection rate", ui.fmt_pct(t["binary"]["detection_rate"]), "any attack class predicted"),
    ui.card("Benign holdout FPR", ui.fmt_pct(h.get("false_positive_rate"), 2), f"unseen capture {h.get('capture', '—')}"),
    ui.card("Label policy / split", f"{m['label_policy']}", f"{m['split']} split · {m['model']}"),
])

c1, c2 = st.columns([1.15, 1])
labels = [pc["name"] for pc in t["per_class"]]
with c1:
    cm = np.array(t["confusion_matrix"], dtype=float)
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig = go.Figure(go.Heatmap(z=norm, x=labels, y=labels, colorscale=ui.BLUE_RAMP, zmin=0, zmax=1, xgap=2, ygap=2,
                               text=[[f"{v / 1000:.1f}k" if v >= 1000 else str(int(v)) for v in row] for row in cm],
                               texttemplate="%{text}", textfont=dict(size=10, color="#ffffff"),
                               customdata=norm, hovertemplate="true %{y}<br>pred %{x}<br>%{text} flows (%{customdata:.1%} of row)<extra></extra>",
                               colorbar=dict(title=dict(text="row share", font=dict(color=ui.INK2)), tickformat=".0%", tickfont=dict(color=ui.MUTED))))
    fig.update_layout(title="Confusion matrix (counts; color = share of true class)")
    fig.update_yaxes(autorange="reversed", title="true class")
    fig.update_xaxes(title="predicted class", tickangle=-40)
    st.plotly_chart(ui.style(fig, 520, legend=False), width="stretch")
with c2:
    pc = pd.DataFrame(t["per_class"])
    fig = go.Figure([go.Bar(name=k.capitalize(), y=pc["name"], x=pc[k], orientation="h", marker_color=ui.SERIES[i],
                            marker_line=dict(color=ui.SURFACE, width=2),
                            hovertemplate="%{y}<br>" + k + ": %{x:.3f}<extra></extra>")
                     for i, k in enumerate(["precision", "recall", "f1"])])
    fig.update_layout(barmode="group", title="Per-class performance", bargap=0.25, bargroupgap=0.1)
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(range=[0, 1])
    st.plotly_chart(ui.style(fig, 520), width="stretch")

st.dataframe(pd.DataFrame(t["per_class"]).rename(columns=str.capitalize), hide_index=True, width="stretch")

st.subheader("All trained models")
st.dataframe(pd.DataFrame([{"Model": k, "Label policy": v["label_policy"], "Split": v["split"], "Classes": v["classes"],
                            "Accuracy": v["accuracy"], "Macro F1": v["f1_macro"], "Weighted F1": v["f1_weighted"],
                            "Benign holdout FPR": v.get("benign_holdout_fpr"),
                            "Lab train sets": ", ".join(v.get("lab_train_sets") or [])} for k, v in registry.items()]),
             hide_index=True, width="stretch")

lab = perf.get("lab_validation")
if lab:
    st.subheader("Validation on traffic captured in this lab")
    rows = []
    for s, rep in lab["sets"].items():
        for r in rep["results"]:
            rows.append({"Lab set": s, "Model": r["model"], "Benign flows": r["benign_flows"], "Attack flows": r["attack_flows"],
                         "Benign FPR": r["benign_fpr"], "Attack flagged": r["attack_detected_any_class"],
                         "Attack correct class": r["attack_detected_correct_class"]})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=320)

noise = m.get("label_noise_analysis", {}).get("per_class")
if noise:
    st.subheader("Dataset label-noise analysis")
    st.caption("Share of each class's flows matching infrastructure service signatures of the benign background capture.")
    names = api.classes()
    st.dataframe(pd.DataFrame([{"Label": k, "Class": names.get(str(k), k), "Flows": v["flows"],
                                "Background-like": v["background_like"],
                                "Fraction": v["background_like_fraction"], "Remaining": v["remaining_flows"]}
                               for k, v in noise.items()]), hide_index=True, width="stretch")
st.info("Single reconnaissance HTTP flows from this lab are not separable from benign requests at the flow level; the "
        "deployed system therefore combines this per-flow model with the per-source flow-burst detector. "
        "No claim is made that any model outperforms published results.")
