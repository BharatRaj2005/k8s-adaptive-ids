"""Attack Simulator UI: configuration dialog and lifecycle panel (Live Security Monitoring page)."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from components import api, ui

ACTIVE = ("requested", "running", "processing")
CATEGORY_LABELS = {"recon": "Reconnaissance", "benign": "Benign traffic testing"}
APP_LABELS = {"nodered": "Node-RED", "grafana": "Grafana", "influxdb": "InfluxDB", "all": "All three applications"}
STATUS_STATE = {"completed": "good", "cancelled": "neutral", "requested": "neutral", "running": "neutral",
                "processing": "neutral", "failed": "critical", "timeout": "critical", "interrupted": "warning"}
STAGE_LABELS = [("requested", "Simulation requested"), ("job_created", "Kubernetes Job created"),
                ("pod_running", "Generator pod running"), ("traffic_generated", "Traffic generated"),
                ("pcap_captured", "PCAP captured"), ("conversion", "CICFlowMeter conversion"),
                ("classification", "ML classification"), ("behavioural", "Behavioural detection"),
                ("results_stored", "Results stored"), ("cleaned_up", "Generator cleaned up")]


@st.dialog("Attack Simulator", width="large")
def dialog() -> None:
    cat, _ = api.simulation_scenarios()
    if not cat:
        st.error("The simulator needs the backend (and the cluster); it is unreachable.")
        return
    st.caption("Launches **one** controlled traffic-generation Job in the `ids-traffic` namespace against a lab "
               "application. Scanners only request paths (GET / HEAD / OPTIONS); nothing is exploited. Capture is "
               "attached to (or started for the run), and the Job and its Pod are deleted automatically once the "
               "traffic has been captured and classified.")
    category = st.radio("Attack category", list(cat["categories"]), format_func=CATEGORY_LABELS.get, horizontal=True,
                        key="sim_category")
    scenarios = cat["categories"][category]
    key = st.selectbox("Scanner profile" if category == "recon" else "Traffic profile", list(scenarios),
                       format_func=lambda k: scenarios[k]["label"], key=f"sim_scenario_{category}")
    sc = scenarios[key]
    st.caption(f"{sc['description']} · generator profile `{sc['profile']}`")
    if sc["all_apps"]:
        st.selectbox("Target application", ["all"], format_func=APP_LABELS.get, disabled=True, key="sim_target_all",
                     help="This scanner always sweeps every lab application.")
        target = "all"
    else:
        target = st.selectbox("Target application", list(cat["targets"]), format_func=APP_LABELS.get, key="sim_target")
    lim, d = cat["limits"], sc["defaults"]
    c1, c2, c3 = st.columns(3)
    duration = c1.slider("Duration (s)", int(lim["duration_s"][0]), int(lim["duration_s"][1]), int(d["duration_s"]),
                         step=5, key=f"sim_dur_{category}_{key}", help="Hard limit; the generator stops at this time.")
    rate = c2.slider("Request rate (req/s)", float(lim["rate_per_s"][0]), float(lim["rate_per_s"][1]),
                     float(d["rate_per_s"]), step=0.1, key=f"sim_rate_{category}_{key}",
                     help="Approximate total rate across all workers.")
    max_req = c3.number_input("Max requests", int(lim["max_requests"][0]), int(lim["max_requests"][1]),
                              int(d["max_requests"]), step=10, key=f"sim_req_{category}_{key}")
    expected = min(int(max_req), int(rate * duration))
    st.markdown(ui.badge(f"≈ {expected:,} requests over ≤ {duration} s", "neutral")
                + ui.badge(f"target: {APP_LABELS[target]}", "neutral")
                + ui.badge("ground truth: generator pod IP + connection log", "neutral"), unsafe_allow_html=True)
    confirm = st.checkbox("I confirm starting this controlled lab simulation", key="sim_confirm")
    b1, b2 = st.columns(2)
    if b1.button("START SIMULATION", type="primary", width="stretch", disabled=not confirm,
                 icon=":material/play_circle:"):
        ok, res = api.write("POST", "/api/simulations", {"category": category, "scenario": key, "target": target,
                                                          "duration_s": int(duration), "rate_per_s": float(rate),
                                                          "max_requests": int(max_req)})
        if ok:
            st.session_state["sim_active"] = True
            st.session_state["mon_msg"] = ("success", f"Simulation {res['run_id']} started")
            st.rerun()
        else:
            st.error(f"Not started: {res}")
    if b2.button("Close", width="stretch"):
        st.rerun()


def _fmt_time(ts) -> str:
    return str(ts)[11:19] if ts else "—"


def panel(runs: list[dict], online: bool) -> None:
    """Lifecycle tracker and results of the latest run (plus a table of recent runs)."""
    if not runs:
        return
    run = runs[0]
    params = run.get("params") or {}
    active = run["status"] in ACTIVE
    with st.container(border=True):
        h1, h2 = st.columns([4, 1.3], vertical_alignment="center")
        h1.markdown(f"**🧪 Lab simulation `{run['run_id']}`** &nbsp;"
                    + ui.badge(run["status"], STATUS_STATE.get(run["status"], "neutral"))
                    + ui.badge(CATEGORY_LABELS.get(run["category"], run["category"]), "neutral"),
                    unsafe_allow_html=True)
        if active and online:
            with h2.popover("Cancel simulation", icon=":material/cancel:", width="stretch"):
                st.write("Stop the generator now? Its logs are kept and the captured windows are still processed.")
                if st.button("Yes, cancel the run", type="primary", key=f"sim_cancel_{run['run_id']}"):
                    ok, res = api.write("POST", f"/api/simulations/{run['run_id']}/cancel")
                    st.session_state["mon_msg"] = ("info", "Cancellation requested") if ok else ("error", f"{res}")
                    st.rerun()
        failed = run["status"] in ("failed", "timeout", "interrupted")
        reached = run.get("stages") or {}
        upcoming = next((k for k, _ in STAGE_LABELS if k not in reached), None)
        ui.stage_tracker(STAGE_LABELS, reached, upcoming if active or failed else None, failed=failed)
        cleanup = run.get("cleanup") or {}
        cleanup_txt = ("✓ Job and Pod deleted" if cleanup.get("ok") else
                       ("✕ leftovers: " + ", ".join(cleanup.get("remaining") or []) if cleanup else "pending"))
        ui.card_row([
            ui.card("Scanner / profile", params.get("label", run["profile"]), f"generator: {run['profile']}"),
            ui.card("Target", ", ".join(APP_LABELS.get(a, a) for a in str(run["target"]).split(",")),
                    f"{params.get('rate_per_s', '—')} req/s · ≤ {params.get('duration_s', '—')} s · max {params.get('max_requests', '—')}"),
            ui.card("Generator pod", run.get("pod_ip") or "—", run.get("pod_name") or "not started",
                    help="Source IP of the generated traffic; used as ground truth for the run."),
            ui.card("Started", _fmt_time(run.get("created_at")),
                    f"traffic {_fmt_time(run.get('traffic_start'))}–{_fmt_time(run.get('traffic_end'))} UTC"),
            ui.card("Requests sent", ui.fmt_int(run.get("requests")), f"{ui.fmt_int(run.get('connections'))} connections"),
        ])
        st.write("")
        ui.card_row([
            ui.card("Captured packets", ui.fmt_int(run.get("packets")),
                    f"in {len(run.get('capture_ids') or [])} window(s), all traffic",
                    help="Packets of every capture window overlapping the run (includes background traffic)."),
            ui.card("Extracted flows", ui.fmt_int(run.get("flows")), f"{ui.fmt_int(run.get('detections'))} from the generator pod"),
            ui.card("Detected attacks", ui.fmt_int(run.get("attacks")), "ML attack verdicts on generator flows",
                    state="critical" if run.get("attacks") else None,
                    help="Classifier verdicts on generated lab traffic. They are detections, not successful exploits."),
            ui.card("Behavioural alerts", ui.fmt_int(run.get("alerts")), "naming the generator pod",
                    state="serious" if run.get("alerts") else None),
            ui.card("Cleanup", "done" if cleanup.get("ok") else ("check" if cleanup else "pending"), cleanup_txt,
                    state="good" if cleanup.get("ok") else ("critical" if cleanup else None)),
        ])
        if run.get("error"):
            (st.info if run["status"] == "cancelled" else st.warning)(run["error"])
        st.caption("Simulated lab traffic: predictions on it show what the detectors flag. They never indicate that an "
                   "exploit succeeded; scanners only request paths.")
        e1, e2 = st.columns(2)
        with e1.expander("Generator log (last 60 lines)"):
            if online:
                logs, _ = api.simulation_logs(run["run_id"])
                lines = (logs or {}).get("lines") or []
                st.code("\n".join(lines) if lines else "no log lines yet", language="json")
            else:
                st.caption("Needs the backend.")
        with e2.expander(f"Recent simulation runs ({len(runs)})"):
            st.dataframe(pd.DataFrame({
                "Run": [r["run_id"] for r in runs], "Status": [r["status"] for r in runs],
                "Profile": [(r.get("params") or {}).get("label", r["profile"]) for r in runs],
                "Target": [r["target"] for r in runs], "Requests": [r.get("requests") for r in runs],
                "Attacks": [r.get("attacks") for r in runs], "Alerts": [r.get("alerts") for r in runs],
                "Cleanup": [json.dumps((r.get("cleanup") or {}).get("ok")) for r in runs],
            }), hide_index=True, width="stretch")
