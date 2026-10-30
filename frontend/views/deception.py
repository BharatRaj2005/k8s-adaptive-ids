import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, ui

st.title("Adaptive Deception (MAPE-K)")

pol, _ = api.policy()
profiles = list((pol or {}).get("profiles", {}))


@st.fragment(run_every="5s" if st.session_state.get("auto_refresh") else None)
def status_panel():
    s, mode = api.deception_status()
    ui.mode_banner(mode)
    if not s:
        ui.empty("Controller state unavailable.")
        return
    st.markdown(
        ui.badge("Automatic deception ENABLED" if s["enabled"] else "Automatic deception DISABLED",
                 "good" if s["enabled"] else "warning")
        + ui.badge("Controller loop running" if s.get("loop_running") else "Controller loop stopped",
                   "good" if s.get("loop_running") else "critical")
        + ui.badge("Kubernetes reachable" if s.get("kubernetes_available") else "Kubernetes unavailable",
                   "good" if s.get("kubernetes_available") else "critical"), unsafe_allow_html=True)

    stage = s.get("stage", "idle")
    st.markdown("".join(
        f'<span class="ids-stage{" on" if stage == key else ""}">{label}</span>' for key, label in
        [("monitor", "M · Monitor"), ("analyze", "A · Analyze"), ("plan", "P · Plan"), ("execute", "E · Execute"),
         ("knowledge", "K · Knowledge"), ("idle", "idle (between cycles)")]), unsafe_allow_html=True)
    last = s.get("last_cycle") or {}
    if last:
        hk = last.get("housekeeping", {})
        st.caption(f"Last cycle #{last.get('cycle_id')} at {str(last.get('started_at', ''))[11:19]} UTC, "
                   f"{last.get('duration_ms', 0):.0f} ms · evidence {last.get('evidence') or {}} · "
                   f"actions {len(last.get('actions') or [])} · interactions collected {hk.get('interactions', 0)} · "
                   f"expired {hk.get('expired', [])}")

    act = ui.df(s.get("active_decoys"))
    dec = ui.df(api.decisions(limit=1000)[0])
    st.subheader("Active decoys")
    if act.empty:
        ui.empty("No decoy is currently deployed.")
    else:
        why = dec.set_index("id")["reason"].to_dict() if not dec.empty else {}
        trig = dec.set_index("id")["trigger"].to_dict() if not dec.empty else {}
        st.dataframe(pd.DataFrame({
            "Decoy": act["name"], "Profile": act["profile"], "Status": act["status"], "Replicas": act["replicas"],
            "Service": act["service_ip"].fillna("") + ":" + act["port"].astype("Int64").astype(str),
            "Deployed": act["created_at"].str.slice(11, 19), "Ready in (s)": act["deploy_seconds"].astype(float).round(1),
            "Expires (UTC)": act["expires_at"].str.slice(11, 19),
            "Trigger": [("SIMULATED · " if sim else "") + str(trig.get(i, "")) for i, sim in zip(act["decision_id"], act["simulated"])],
            "Why activated": [why.get(i, "") for i in act["decision_id"]],
        }), hide_index=True, width="stretch")


status_panel()

st.subheader("Controls")
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown("**Automatic deployment**")
    if st.button("Enable automatic deception", type="primary", width="stretch"):
        ok, res = api.write("POST", "/api/deception/enable")
        st.toast("Deception enabled" if ok else f"Failed: {res}")
    if st.button("Disable automatic deception", width="stretch"):
        ok, res = api.write("POST", "/api/deception/disable")
        st.toast("Deception disabled" if ok else f"Failed: {res}")
    if st.button("Run one MAPE-K cycle now", width="stretch"):
        ok, res = api.write("POST", "/api/deception/cycle")
        st.toast(f"Cycle {res.get('cycle_id')} done" if ok else f"Failed: {res}")
with c2:
    st.markdown("**Manual decoy control**")
    prof = st.selectbox("Profile", profiles, format_func=lambda p: f"{p} — {pol['profiles'][p]['description']}")
    if st.button("Deploy selected decoy", width="stretch"):
        ok, res = api.write("POST", "/api/deception/decoys", {"profile": prof})
        (st.success if ok else st.error)(f"Deployed {res['name']}" if ok else f"Failed: {res}")
    active_names = [d["name"] for d in (api.deception_status()[0] or {}).get("active_decoys", [])]
    rm = st.selectbox("Active decoy", active_names or ["—"])
    if st.button("Remove selected decoy", width="stretch", disabled=not active_names):
        ok, res = api.write("DELETE", f"/api/deception/decoys/{rm}")
        (st.success if ok else st.error)(f"Removed {rm}" if ok else f"Failed: {res}")
with c3:
    st.markdown('**Simulated test event** <span class="ids-sim">SIMULATED</span>', unsafe_allow_html=True)
    with st.form("sim"):
        cls = st.selectbox("Attack class", list((pol or {}).get("attack_policy", {})))
        conf = st.slider("Confidence", 0.0, 1.0, 0.95, 0.01)
        sip = st.text_input("Source IP (optional)", "192.0.2.10")
        cnt = st.number_input("Repeat count", 1, 100, 1)
        if st.form_submit_button("Trigger simulated event", width="stretch"):
            ok, res = api.write("POST", "/api/deception/test-event",
                                {"attack_class": cls, "confidence": conf, "src_ip": sip or None, "count": int(cnt),
                                 "note": "dashboard test"})
            (st.warning if ok else st.error)(
                f"SIMULATED event #{res['simulated_event_id']} queued — not an ML detection, excluded from ML metrics"
                if ok else f"Failed: {res}")


@st.fragment(run_every="5s" if st.session_state.get("auto_refresh") else None)
def history():
    t1, t2, t3, t4 = st.tabs(["MAPE-K decision history", "Decoy interactions", "Deployment history", "Attack → decoy policy"])
    with t1:
        inc = st.toggle("Include simulated decisions", True)
        dec = ui.df(api.decisions(limit=1000, include_simulated=inc)[0])
        if dec.empty:
            ui.empty("No decisions yet.")
        else:
            acts = st.multiselect("Actions", sorted(dec["action"].unique()), default=sorted(dec["action"].unique()))
            dec = dec[dec["action"].isin(acts)]
            st.dataframe(pd.DataFrame({
                "#": dec["id"], "Time (UTC)": dec["created_at"].str.slice(11, 19),
                "Trigger": dec["trigger"], "Simulated": dec["simulated"].map({1: "SIMULATED", 0: ""}),
                "Action": dec["action"], "Decoy": dec["decoy_profile"].fillna(""), "Result": dec["result"],
                "Reason": dec["reason"], "Source IP": dec["src_ip"].fillna(""),
                "Attack class": dec["attack_class"].fillna(""), "Assessment": dec["assessment"].fillna(""),
                "Max conf.": dec["max_confidence"], "Evidence": dec["evidence_count"], "Cycle": dec["cycle_id"],
            }), hide_index=True, width="stretch", height=420,
                column_config={"Reason": st.column_config.TextColumn(width="large"),
                               "Max conf.": st.column_config.NumberColumn(format="%.2f")})
    with t2:
        it = ui.df(api.interactions(2000)[0])
        if it.empty:
            ui.empty("No decoy interactions recorded.")
        else:
            types = ["page_request", "unknown_path", "data_submission"]
            g = it.groupby(["decoy_name", "interaction_type"]).size().unstack(fill_value=0).reindex(columns=types, fill_value=0)
            fig = go.Figure([go.Bar(name=t, x=g.index, y=g[t], marker_color=ui.SERIES[i],
                                    marker_line=dict(color=ui.SURFACE, width=2),
                                    hovertemplate="%{x}<br>" + t + ": %{y}<extra></extra>") for i, t in enumerate(types)])
            fig.update_layout(barmode="group", title="Interactions by decoy and type")
            st.plotly_chart(ui.style(fig, 280), width="stretch")
            st.dataframe(pd.DataFrame({
                "Time (UTC)": it["ts"].str.slice(0, 19).str.replace("T", " "), "Decoy": it["decoy_name"],
                "Category": it["decoy_profile"], "Source IP": it["src_ip"], "Method": it["method"], "Endpoint": it["path"],
                "Status": it["status"], "Type": it["interaction_type"], "Decision #": it["decision_id"],
                "Detection #": it["detection_id"],
            }), hide_index=True, width="stretch", height=360)
    with t3:
        dd = ui.df(api.decoys(500)[0])
        if dd.empty:
            ui.empty("No decoys deployed yet.")
        else:
            st.dataframe(pd.DataFrame({
                "Decoy": dd["name"], "Profile": dd["profile"], "Status": dd["status"], "Replicas": dd["replicas"],
                "Created (UTC)": dd["created_at"].str.slice(0, 19).str.replace("T", " "),
                "Ready in (s)": dd["deploy_seconds"], "Expires": dd["expires_at"].fillna("").str.slice(11, 19),
                "Removed": dd["removed_at"].fillna("").str.slice(11, 19), "Simulated": dd["simulated"].map({1: "SIMULATED", 0: ""}),
                "Decision #": dd["decision_id"], "Error": dd["error"].fillna(""),
            }), hide_index=True, width="stretch", height=360)
    with t4:
        if pol:
            st.dataframe(pd.DataFrame([{"Attack class (ML)": k, "Decoy profiles (preferred first)": ", ".join(v)}
                                       for k, v in pol["attack_policy"].items()]), hide_index=True, width="stretch")
            st.dataframe(pd.DataFrame([{"Flow burst to port": k, "Decoy profiles": ", ".join(v)}
                                       for k, v in pol["behavior_policy"].items()]), hide_index=True, width="stretch")
            th = pol["thresholds"]
            st.markdown(
                f"- **High confidence** ≥ {th['high_confidence']}: act after policy validation\n"
                f"- **Medium** ≥ {th['medium_confidence']}: act only with ≥ {th['repeat_count']} detections in "
                f"{th['repeat_window_seconds']} s or a corroborating flow burst\n"
                f"- **Low**: recorded and monitored · **Benign**: never deploys\n"
                f"- Limits: max {pol['max_active_decoys']} decoys, ≤ {pol['max_replicas']} replicas, TTL "
                f"{pol['decoy_ttl_seconds']} s (extended by interactions, capped at {pol['max_lifetime_seconds']} s), "
                f"cooldown {pol['cooldown_seconds']} s, redeploy cooldown {pol['redeploy_cooldown_seconds']} s\n"
                f"- Density grows for {', '.join(pol['scale_on_repeat'])} on repeated evidence and for any decoy with ≥ "
                f"{pol['engagement']['scale_up_interactions']} interactions in {pol['engagement']['window_seconds']} s")


history()
