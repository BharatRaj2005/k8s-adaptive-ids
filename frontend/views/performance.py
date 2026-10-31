import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Model Performance")
st.caption("Three kinds of evidence, kept apart: (1) the dataset test split, (2) traffic recorded in this lab and "
           "never used for training or tuning, (3) live counts from this cluster, which has no ground truth. They are "
           "never combined into one figure.")

perf, mode = api.model_performance()
ui.mode_banner(mode)
if not perf or "test" not in perf:
    ui.empty("No trained model metrics found.")
    st.stop()
ev = api.evaluation()[0] or {}
registry = perf.get("registry", {})

tab_test, tab_cmp, tab_lab, tab_unknown, tab_live = st.tabs(
    ["Dataset test", "Model comparison", "Independent lab", "Unseen applications", "Live cluster"])


def rate(x):
    """'n/d (p%)' for {'n','of','rate'} dicts."""
    if not x or not x.get("of"):
        return "—"
    return f"{x['n']}/{x['of']} ({100 * x['rate']:.1f}%)"


# --- 1. dataset test -----------------------------------------------------------------------
with tab_test:
    names = sorted(registry)
    name = st.selectbox("Model", names, index=names.index(perf["name"]) if perf.get("name") in names else 0,
                        format_func=lambda n: n + ("  (active)" if n == perf.get("name") else ""))
    m = perf if name == perf.get("name") else api.model_metrics(name)[0]
    t, lat, h = m["test"], m["latency"], m.get("benign_holdout", {})
    st.caption(f"Held-out temporal test split (latest 25 % of every capture), label policy **{m['label_policy']}**. "
               "Models trained on the published labels are scored against those labels here; the evidence-label "
               "comparison of all models is on the next tab.")
    ui.card_row([
        ui.card("Macro F1", f"{t['f1_macro']:.3f}", f"{len(t['labels'])} classes, unweighted"),
        ui.card("Macro recall", f"{t['recall_macro']:.3f}"),
        ui.card("Benign FPR", ui.fmt_pct(t["binary"]["false_positive_rate"], 2), "benign flows flagged as attack"),
        ui.card("Attack recall", ui.fmt_pct(t["binary"]["detection_rate"]), "attack flows flagged as any attack"),
    ])
    st.write("")
    ui.card_row([
        ui.card("Accuracy", f"{t['accuracy']:.4f}", f"{t['test_rows']:,} test flows; dominated by benign"),
        ui.card("Weighted F1", f"{t['f1_weighted']:.4f}"),
        ui.card("Single-flow latency", f"{lat['single_flow_median_ms']:.1f} ms", f"median; p95 {lat['single_flow_p95_ms']:.1f} ms"),
        ui.card("Batch throughput", f"{lat['batch_per_flow_us']:.0f} µs/flow", f"{lat['batch_rows']:,} flows"),
    ])
    c1, c2 = st.columns([1.15, 1])
    labels = [pc["name"] for pc in t["per_class"]]
    with c1:
        cm = np.array(t["confusion_matrix"], dtype=float)
        norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
        fig = go.Figure(go.Heatmap(z=norm, x=labels, y=labels, colorscale=ui.BLUE_RAMP, zmin=0, zmax=1, xgap=2, ygap=2,
                                   text=[[f"{v / 1000:.1f}k" if v >= 1000 else str(int(v)) for v in row] for row in cm],
                                   texttemplate="%{text}", textfont=dict(size=12, color="#ffffff"),
                                   customdata=norm, hovertemplate="true %{y}<br>pred %{x}<br>%{text} flows (%{customdata:.1%} of row)<extra></extra>",
                                   colorbar=dict(title=dict(text="row share", font=dict(color=ui.INK2)), tickformat=".0%", tickfont=dict(color=ui.MUTED))))
        fig.update_layout(title="Confusion matrix (counts; color = share of the true class)")
        fig.update_yaxes(autorange="reversed", title="true class")
        fig.update_xaxes(title="predicted class", tickangle=-30)
        st.plotly_chart(ui.style(fig, 480, legend=False), width="stretch")
    with c2:
        pc = pd.DataFrame(t["per_class"])
        fig = go.Figure(go.Bar(y=pc["name"], x=pc["f1"], orientation="h", marker_color=ui.SERIES[0],
                               text=[f"{v:.2f} (n={n})" for v, n in zip(pc["f1"], pc["support"])], textposition="outside",
                               textfont=dict(color=ui.INK2), hovertemplate="%{y}<br>F1 %{x:.3f}<extra></extra>"))
        fig.update_layout(title="Per-class F1 (n = test flows)")
        fig.update_yaxes(autorange="reversed")
        fig.update_xaxes(range=[0, 1.25], tickvals=[0, 0.25, 0.5, 0.75, 1])
        st.plotly_chart(ui.style(fig, 480, legend=False), width="stretch")
    cols = ["name", "precision", "recall", "f1", "support"] + (["recall_ci95"] if "recall_ci95" in pc else [])
    st.dataframe(pc[cols].rename(columns={"name": "Class", "recall_ci95": "Recall 95% CI"}).rename(columns=str.capitalize),
                 hide_index=True, width="stretch")
    if (pc["support"] < 10).any():
        st.warning("Classes with fewer than 10 test flows have very wide confidence intervals; one flow changes their F1 "
                   "by 0.2–0.5. Compare models on benign FPR and recon results instead.")
    with st.expander("All trained models (registry)"):
        st.dataframe(pd.DataFrame([{"Model": k, "Label policy": v["label_policy"], "Split": v["split"], "Classes": v["classes"],
                                    "Macro F1": v["f1_macro"], "Macro recall": v.get("recall_macro"),
                                    "Benign FPR": v.get("benign_fpr"), "Accuracy": v["accuracy"],
                                    "Lab train sets": ", ".join(v.get("lab_train_sets") or [])} for k, v in registry.items()]),
                     hide_index=True, width="stretch")

# --- 2. model comparison ------------------------------------------------------------------
with tab_cmp:
    cmp = ev.get("comparison")
    if not cmp:
        ui.empty("No model comparison yet (python -m src.detection.experiments).")
    else:
        st.caption(f"Same protocol for every model: evidence labels, temporal test split of "
                   f"{cmp['protocol']['test_rows']:,} flows, threshold tuned on validation, independent lab sets "
                   f"{', '.join(cmp['protocol']['lab_eval_sets'])}. Active model: **{ev.get('active_model')}**. "
                   "Details: reports/model_comparison.md.")
        rows = [{"Model": e["name"] + ("  (baseline)" if e is cmp["baseline"] else "")
                 + ("  (active)" if e["name"] == ev.get("active_model") else ""),
                 "Macro F1": e["f1_macro"], "Macro recall": e["recall_macro"], "Benign FPR": e["benign_fpr"],
                 "Attack recall": e["attack_recall"],
                 "Lab benign FPR": (e["lab"].get("benign_eval_b") or {}).get("benign_fpr"),
                 "Lab recon recall": (e["lab"].get("recon_run2") or {}).get("attack_recall"),
                 "LOCO mean FPR": e["loco_mean_fpr"], "Size MB": round(e["model_mb"], 1), "Peak RSS MB": e["peak_rss_mb"],
                 "Accuracy": e["accuracy"]} for e in [cmp["baseline"], *cmp["candidates"]]]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", column_config={
            "Macro F1": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.3f"),
            "Macro recall": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.3f"),
            **{k: st.column_config.NumberColumn(format="%.4f") for k in ("Benign FPR", "Lab benign FPR", "LOCO mean FPR")},
            **{k: st.column_config.NumberColumn(format="%.3f") for k in ("Attack recall", "Lab recon recall", "Accuracy")}})
        df = pd.DataFrame(rows)
        fig = go.Figure(go.Scatter(x=df["Benign FPR"] * 100, y=df["Macro F1"], mode="markers+text", text=df["Model"].str.split().str[0],
                                   textposition="top center", textfont=dict(color=ui.INK2, size=11),
                                   marker=dict(size=11, color=ui.SERIES[0], line=dict(color=ui.SURFACE, width=2)),
                                   hovertemplate="%{text}<br>benign FPR %{x:.2f}%<br>macro F1 %{y:.3f}<extra></extra>"))
        fig.update_layout(title="Macro F1 vs benign false-positive rate (test split; up and left is better)")
        fig.update_xaxes(title="benign FPR (%)")
        fig.update_yaxes(title="macro F1", range=[0, 1])
        st.plotly_chart(ui.style(fig, 380, legend=False), width="stretch")

# --- 3. independent lab -------------------------------------------------------------------
with tab_lab:
    sessions = ev.get("behaviour") or []
    if not sessions:
        ui.empty("No behavioural evaluation yet (python -m src.detection.behavior_eval).")
    for s in sessions:
        role = "calibration (used during development)" if s["role"] == "calibration" else "held-out evaluation"
        st.subheader(f"{s['name']} · {role}")
        st.caption(f"{s['windows']} windows. Unit: (window, source) pairs. Fixed = original flow-burst rule; "
                   "Adaptive = fixed + learned thresholds; ML = ≥2 attack flows of a source; Hybrid = adaptive or ML. "
                   "Behavioural alerts and ML detections stay separate records.")
        st.dataframe(pd.DataFrame([{"Detector": d, "Detection rate": rate(r["detection_rate"]),
                                    "False-positive rate": rate(r["false_positive_rate"]),
                                    "Precision": rate(r["precision"]),
                                    "Alerts / window": round(r["alerts_per_window_mean"], 2)}
                                   for d, r in s["results"].items()]), hide_index=True, width="stretch")
        scen = list(next(iter(s["results"].values()))["scenarios"])
        if scen:
            st.dataframe(pd.DataFrame([{"Scenario": n, "Req/s": s["results"]["fixed"]["scenarios"][n]["rate_per_s"],
                                        **{f"{d} windows": f"{r['scenarios'][n]['windows']['n']}/{r['scenarios'][n]['windows']['of']}"
                                           for d, r in s["results"].items()},
                                        **{f"{d} delay s": r["scenarios"][n]["delay_s"] for d, r in s["results"].items()}}
                                       for n in scen]), hide_index=True, width="stretch")
    st.caption("Details and limitations: reports/behavioural_detection.md.")

# --- 4. unseen applications ---------------------------------------------------------------
with tab_unknown:
    unk = ev.get("unknown")
    if not unk:
        ui.empty("No unknown-traffic evaluation yet (python -m src.detection.loao_eval).")
    else:
        c = unk["config"]
        st.caption("Leave-one-application-out: all benign traffic of one application removed from training; thresholds "
                   "calibrated without it. Unknown = reported as 'Unknown / Requires Investigation', never as an attack "
                   f"and never acted on by the deception controller. Active: enabled={c['enabled']}, checks={c['checks']}. "
                   "Details: reports/unknown_traffic.md.")
        rows = []
        for f in unk["folds"]:
            for v, x in f["variants"].items():
                rows.append({"Held-out application": f["application"], "Check": v,
                             "Held-out benign → attack": rate(x["held_out_fpr"]),
                             "Held-out benign → unknown": rate(x["held_out_unknown"]),
                             "Known benign → unknown": rate(x["known_unknown"]),
                             "Attacks detected": rate(x["attacks_detected"]),
                             "Attacks → unknown": rate(x["attacks_unknown"])})
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=420)

# --- 5. live cluster ----------------------------------------------------------------------
with tab_live:
    mt = api.metrics()[0] or {}
    st.caption("Counts from the knowledge base (all stored flows; dataset replays included and labelled by source). "
               "Live traffic has no ground truth, so no accuracy is computed here.")
    by_type = mt.get("behavior_alerts_by_type") or {}
    ui.card_row([
        ui.card("Known benign", ui.fmt_int(mt.get("benign_flows")), "classifier: benign"),
        ui.card("Known attack classes", ui.fmt_int(mt.get("malicious_flows")), "ML verdict on a familiar service"),
        ui.card("Unknown / investigate", ui.fmt_int(mt.get("unknown_flows")), "attack verdict on an unfamiliar service"),
        ui.card("Behavioural alerts", ui.fmt_int(sum(by_type.values())),
                " · ".join(f"{k} {v}" for k, v in by_type.items()) or "none"),
    ])
    src = mt.get("flows_by_source") or {}
    if src:
        st.dataframe(pd.DataFrame([{"Data source": ui.SOURCE_LABELS.get(k, k), "Flows": v} for k, v in src.items()]),
                     hide_index=True, width="stretch")
