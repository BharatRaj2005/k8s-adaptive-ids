"""Live Security Monitoring: capture control, per-window classification feed, charts and window history.

Replaces the former Traffic Capture and Live Traffic Monitoring pages (their dataset replay and
all-sources history are kept in the expander at the bottom).
"""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import api, simulator, ui

WINDOWS = 60            # capture windows covered by counters-per-window, charts and history
FEED_LIMIT = 300        # rows fetched when the feed (re)starts
FEED_KEEP = 1000        # rows kept in the browser session
MECHANISMS = {"All": None, "ML only": "ml", "Behavioural only": "behavioural", "ML + behavioural": "both",
              "No detection": "none"}
STATUSES = {"All": None, "Benign": "benign", "Malicious": "attack", "Unknown": "unknown"}
ORIGINS = {"All": None, "Observed traffic": "observed", "Lab simulation": "simulation"}
MECH_LABEL = {(True, True): "ML + behavioural", (True, False): "ML", (False, True): "Behavioural", (False, False): "—"}

st.title("Live Security Monitoring")
st.caption("tcpdump on cni0 → PCAP window → CICFlowMeter → ML classifier + behavioural detector → SQLite. "
           "Results appear once a capture window has been processed (adaptive 5 / 10 / 30 s windows plus about one "
           "second of processing); this is window-based detection, not per-packet.")

class_list = sorted(set(api.classes().values()))


def _interval():
    return "3s" if st.session_state.get("auto_refresh") or st.session_state.get("sim_active") else None


def toolbar(ov, mode):
    cap = (ov or {}).get("capture") or {}
    running, online = bool(cap.get("running")), mode == "live"
    c = st.columns([1.45, 1.45, 1.2, 1.5, 1.25, 2.2], vertical_alignment="bottom")
    windows = c[2].number_input("Capture windows", 0, 10000, 0, key="mon_windows", disabled=running or not online,
                                help="Stop after this many windows; 0 = until stopped.")
    if c[0].button("Start monitoring", type="primary", icon=":material/play_arrow:", width="stretch",
                   disabled=running or not online, help=None if online else "needs the backend"):
        ok, res = api.write("POST", "/api/capture/start", {"windows": int(windows) or None, "process": True})
        st.session_state["mon_msg"] = ("success", "Monitoring started") if ok else ("error", f"Start failed: {res}")
        st.rerun()
    if c[1].button("Stop monitoring", icon=":material/stop:", width="stretch", disabled=not running or not online,
                   help="Finishes and processes the window in progress."):
        with st.spinner("Stopping: finishing and processing the current window…"):
            ok, res = api.write("POST", "/api/capture/stop")
        st.session_state["mon_msg"] = ("success", "Monitoring stopped") if ok else ("error", f"Stop failed: {res}")
        st.rerun()
    simulator_slot = c[3]
    auto = c[4].toggle("Auto refresh", value=bool(st.session_state.get("auto_refresh")), key="mon_auto",
                       help="Poll the backend every 3 s (always on while a simulation is active).")
    if auto != bool(st.session_state.get("auto_refresh")):
        st.session_state["auto_refresh"] = auto
        st.rerun()
    status = cap.get("status", "unknown")
    badges = ui.badge(f"Monitoring {'running' if running else status.replace('_', ' ')}",
                      "good" if running else ("warning" if status in ("error", "stopped_unexpectedly") else "neutral"))
    if cap.get("interface"):
        badges += ui.badge(f"Interface {cap['interface']}", "neutral")
    if running and cap.get("window_limit"):
        badges += ui.badge(f"{cap.get('windows', 0)}/{cap['window_limit']} windows", "neutral")
    c[5].markdown(badges, unsafe_allow_html=True)
    msg = st.session_state.pop("mon_msg", None)
    if msg:
        getattr(st, msg[0])(msg[1])
    return simulator_slot, running, online


def stats(ov):
    s, cap = ov["summary"], ov.get("capture") or {}
    last = (ov.get("windows") or [{}])[0]
    ui.card_row([
        ui.card("Flows captured", ui.fmt_int(s["total_flows"]), f"{ui.fmt_int(s['lab_simulation_flows'])} from lab simulations",
                help="Classified flows from captured windows (dataset replays excluded)."),
        ui.card("Benign", ui.fmt_int(s["benign_flows"]), state="good"),
        ui.card("Malicious", ui.fmt_int(s["malicious_flows"]), "ML attack verdicts", state="critical"),
        ui.card("Unknown", ui.fmt_int(s["unknown_flows"]), "unprofiled service", state="warning",
                help="Attack verdict on a service without a benign profile: shown for investigation, never acted on "
                     "by the deception controller."),
        ui.card("Behavioural alerts", ui.fmt_int(s["behavior_alerts"]), "per-source bursts", state="serious",
                help="Fixed flow-burst rule and learned per-service thresholds."),
    ])
    st.write("")
    lat = s.get("pipeline_mean_s")
    ui.card_row([
        ui.card("Active simulations", ui.fmt_int(s["active_simulations"]), "controlled lab Jobs"),
        ui.card("Active decoys", ui.fmt_int(s["active_decoys"]), "deployed by the MAPE-K controller"),
        ui.card("Current window", f"{cap['current_window_s']:.0f} s" if cap.get("running") and cap.get("current_window_s") else "—",
                f"last: {last.get('duration_s', 0) or 0:.1f} s, {ui.fmt_int(last.get('packets'))} packets" if last else "",
                help="Adaptive: 5 s after a busy window, 30 s after a quiet one, else 10 s."),
        ui.card("Processing latency", f"{lat:.2f} s" if lat is not None else "—",
                f"window end → stored, mean of last 20 (max {s['pipeline_max_s']:.2f} s)" if lat is not None else "",
                help="Conversion + classification + behavioural detection after a window closes."),
    ])


def _feed_frame(rows):
    d = ui.df(rows)
    if d.empty:
        return d
    d["behavioural"] = d["behavioural"].astype(bool)
    d["verdict"] = [ui.verdict(s, b) for s, b in zip(d["status"], d["behavioural"])]
    return d


def feed(app_ports, runs):
    st.markdown('<div class="ids-section">Live prediction feed</div>', unsafe_allow_html=True)
    f = st.columns([1.5, 1.1, 1.1, 1.0, 1.3, 1.2])
    cls = f[0].selectbox("Attack class", ["All"] + class_list, key="feed_cls")
    src = f[1].text_input("Source IP", key="feed_src").strip() or None
    app = f[2].selectbox("Destination app", ["All"] + list(app_ports), key="feed_app")
    status = f[3].selectbox("Status", list(STATUSES), key="feed_status")
    mech = f[4].selectbox("Detection mechanism", list(MECHANISMS), key="feed_mech")
    origin = f[5].selectbox("Traffic origin", list(ORIGINS), key="feed_origin")
    filters = {"predicted_class": None if cls == "All" else cls, "src_ip": src, "app": None if app == "All" else app,
               "status": STATUSES[status], "mechanism": MECHANISMS[mech], "origin": ORIGINS[origin]}
    key = tuple(sorted(filters.items(), key=lambda kv: kv[0]))
    buf = st.session_state.get("feed_buf")
    if not buf or buf["key"] != key:                      # new filters: start over
        rows, mode = api.monitoring_feed(0, FEED_LIMIT, **filters)
        buf = {"key": key, "frame": _feed_frame(rows), "max_id": 0}
    else:                                                 # same filters: fetch only newer flows
        rows, mode = api.monitoring_feed(buf["max_id"], FEED_KEEP, **filters)
        new = _feed_frame(rows)
        if not new.empty:
            buf["frame"] = pd.concat([new, buf["frame"]], ignore_index=True).drop_duplicates("id").head(FEED_KEEP)
    d = buf["frame"]
    if not d.empty:
        buf["max_id"] = int(d["id"].max())
    st.session_state["feed_buf"] = buf

    if d.empty:
        ui.empty("No classified flows yet for these filters. Start monitoring; flows appear after the first window "
                 "is processed.")
        return
    newest = d["detected_at"].iloc[0]
    st.caption(f"{len(d):,} most recent flows shown (newest first) · last update from window "
               f"{int(d['capture_id'].iloc[0]) if pd.notna(d['capture_id'].iloc[0]) else '—'} at "
               f"{str(newest)[11:19]} UTC · incremental: only flows newer than id {buf['max_id']:,} are fetched next")
    port_app = {p: a for a, ps in app_ports.items() for p in ps}
    # rows fetched before the backend tagged them still get their run: generator pod IP within the run's time span
    spans = [(r["run_id"], r["pod_ip"], r["created_at"], r.get("finished_at")) for r in runs if r.get("pod_ip")]

    def origin_of(run_id, src, dst, detected):
        if isinstance(run_id, str) and run_id:
            return f"🧪 Lab simulation {run_id}"
        for rid, ip, t0, t1 in spans:
            if ip in (src, dst) and str(detected) >= t0 and (not t1 or str(detected) <= t1):
                return f"🧪 Lab simulation {rid}"
        return "Observed"

    def app_of(dport, sport):
        for p in (dport, sport):          # flow direction can be either way round
            if pd.notna(p) and int(p) in port_app:
                return port_app[int(p)]
        return ""

    t = pd.DataFrame({
        "Window": d["capture_id"].astype("Int64"),
        "Flow start (UTC)": d["timestamp"].fillna("").astype(str).str.slice(11, 23),
        "Src IP": d["src_ip"].fillna("unknown"), "Src port": d["src_port"].astype("Int64"),
        "Dst IP": d["dst_ip"].fillna("unknown"), "Dst port": d["dst_port"].astype("Int64"),
        "App": [app_of(dp, sp) for dp, sp in zip(d["dst_port"], d["src_port"])],
        "Protocol": d["protocol"].map(lambda p: ui.PROTOCOLS.get(int(p), str(int(p))) if pd.notna(p) else "unknown"),
        "Predicted class": d["predicted_class"], "Confidence": d["confidence"].astype(float),
        "Verdict": d["verdict"].map(lambda v: ui.VERDICTS[v][0]),
        "Detection": [MECH_LABEL[(s == "attack", b)] for s, b in zip(d["status"], d["behavioural"])],
        "Origin": [origin_of(r, s, t, a) for r, s, t, a in zip(d["sim_run_id"], d["src_ip"], d["dst_ip"], d["detected_at"])],
    })
    colors = {label: ui.STATUS[state] for label, state in ui.VERDICTS.values()}
    styled = t.style.map(lambda v: f"color: {colors.get(v, ui.INK)}; font-weight: 600", subset=["Verdict"])
    st.dataframe(styled, hide_index=True, width="stretch", height=420, column_config={
        "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="%.2f",
                                                      help="Classifier confidence in the predicted class"),
        "Src port": st.column_config.NumberColumn(format="%d"), "Dst port": st.column_config.NumberColumn(format="%d"),
        "Window": st.column_config.NumberColumn(format="%d", help="Capture window id (see history below)"),
        "Verdict": st.column_config.TextColumn(help="Malicious = ML attack verdict · Unknown = attack verdict on an "
                                                    "unprofiled service · Suspicious = ML benign but inside a behavioural alert"),
        "Origin": st.column_config.TextColumn(help="Lab simulation = generated by a controlled Job of the Attack "
                                                   "Simulator (real packets, known ground truth); Observed = everything else"),
    })


def show(fig, height=300, legend=True):
    """ui.style plus a legend row under the title, so the two never collide in narrow columns."""
    fig = ui.style(fig, height, legend)
    fig.update_layout(margin=dict(l=12, r=12, t=72 if legend else 40, b=12), title=dict(y=0.975, yanchor="top"),
                      legend=dict(orientation="h", y=1.0, yanchor="bottom", x=0, xanchor="left", traceorder="normal"))
    st.plotly_chart(fig, width="stretch")


def charts(ov):
    w = ui.df(ov["windows"])
    if w.empty:
        ui.empty("No capture windows yet: the charts fill in as windows are processed.")
        return
    w = w.sort_values("id")
    w["t"] = w["started_at"].fillna("").str.slice(11, 19)
    w["plain_benign"] = w["benign"] - w["suspicious"]
    order = ["benign", "suspicious", "malicious", "unknown"]
    cols = {"benign": "plain_benign", "suspicious": "suspicious", "malicious": "malicious", "unknown": "unknown"}
    bar = dict(marker_line=dict(color=ui.SURFACE, width=2))
    c1, c2 = st.columns(2)
    with c1:
        fig = go.Figure([go.Bar(name=ui.VERDICTS[k][0], x=w["t"], y=w[cols[k]], marker_color=ui.STATUS[ui.VERDICTS[k][1]],
                                customdata=w["id"], hovertemplate="window %{customdata} · %{x}<br>" + ui.VERDICTS[k][0]
                                + ": %{y:,}<extra></extra>", **bar) for k in order])
        fig.update_layout(barmode="stack", title=f"Classified flows per capture window (last {len(w)})",
                          xaxis_title="window start (UTC)", yaxis_title="flows")
        fig.update_xaxes(type="category", nticks=10)
        show(fig)
    with c2:
        tot = {k: int(w[cols[k]].sum()) for k in order}
        fig = go.Figure(go.Bar(x=[tot[k] for k in order], y=[ui.VERDICTS[k][0] for k in order], orientation="h",
                               marker_color=[ui.STATUS[ui.VERDICTS[k][1]] for k in order], text=[f"{tot[k]:,}" for k in order],
                               textposition="outside", textfont=dict(color=ui.INK2),
                               hovertemplate="%{y}: %{x:,} flows<extra></extra>", **bar))
        fig.update_layout(title="Benign vs malicious (flows in the windows shown)", xaxis_title="flows")
        fig.update_yaxes(autorange="reversed")
        fig.update_xaxes(range=[0, max(tot.values() or [1]) * 1.18])
        show(fig, legend=False)
        st.caption("Suspicious = flows inside behavioural alerts that the classifier called benign.")
    c3, c4 = st.columns(2)
    with c3:
        cl = ui.df(ov["classes"])
        cl = cl[cl["predicted_class"] != "Benign"] if not cl.empty else cl
        if cl.empty:
            ui.empty("No attack-class verdicts in these windows.")
        else:
            g = cl.pivot_table(index="predicted_class", columns="status", values="n", aggfunc="sum", fill_value=0)
            fig = go.Figure([go.Bar(name=ui.VERDICTS[v][0], y=g.index, x=g[s], orientation="h",
                                    marker_color=ui.STATUS[ui.VERDICTS[v][1]],
                                    hovertemplate="%{y}<br>" + ui.VERDICTS[v][0] + ": %{x:,}<extra></extra>", **bar)
                             for s, v in (("attack", "malicious"), ("unknown", "unknown")) if s in g.columns])
            fig.update_layout(barmode="stack", title="Attack-class distribution", xaxis_title="flows")
            show(fig)
    with c4:
        sr = ui.df(ov["sources"])
        if sr.empty:
            ui.empty("No source activity in these windows.")
        else:
            sr = sr.sort_values("flows")
            sr["label"] = [f"{ip} 🧪" if isinstance(r, str) and r else ip for ip, r in zip(sr["src_ip"], sr["sim_run_id"])]
            sr["other"] = sr["flows"] - sr["malicious"] - sr["unknown"]
            fig = go.Figure([go.Bar(name=ui.VERDICTS[v][0], y=sr["label"], x=sr[col], orientation="h",
                                    marker_color=ui.STATUS[ui.VERDICTS[v][1]],
                                    hovertemplate="%{y}<br>" + ui.VERDICTS[v][0] + ": %{x:,}<extra></extra>", **bar)
                             for col, v in (("other", "benign"), ("malicious", "malicious"), ("unknown", "unknown"))])
            fig.update_layout(barmode="stack", title="Source IP activity (top 15; 🧪 = lab simulation)", xaxis_title="flows")
            show(fig)
    c5, c6 = st.columns(2)
    with c5:
        a = ui.df(ov["alerts"])
        if a.empty:
            ui.empty("No behavioural alerts in these windows.")
        else:
            a = a.sort_values("id")
            a["t"] = a["detected_at"].str.slice(11, 19)
            sev = a["severity"].fillna("high")
            traces = []
            for level, state, label in (("high", "critical", "✕ Fixed rule (high)"), ("medium", "serious", "! Learned threshold (medium)")):
                s = a[sev == level]
                if len(s):
                    traces.append(go.Scatter(name=label, x=s["t"], y=s["src_ip"], mode="markers",
                                             marker=dict(size=(s["flows"].fillna(1).clip(1, 80) ** 0.5 * 3).clip(lower=8),
                                                         color=ui.STATUS[state], line=dict(color=ui.SURFACE, width=2)),
                                             customdata=s[["dst_port", "flows", "rate_per_s"]].to_numpy(),
                                             hovertemplate="%{x} · %{y} → :%{customdata[0]}<br>%{customdata[1]} flows, "
                                                           "%{customdata[2]:.1f}/s<extra></extra>"))
            fig = go.Figure(traces)
            fig.update_layout(title="Behavioural alert timeline (size = flows in window)", xaxis_title="detected (UTC)")
            fig.update_xaxes(type="category", nticks=8, categoryorder="array", categoryarray=list(dict.fromkeys(a["t"])))
            show(fig)
    with c6:
        lw = w[w["status"] == "classified"]
        if lw.empty:
            ui.empty("No processed windows with timings yet.")
        else:
            fig = go.Figure([
                go.Scatter(name="Window end → stored", x=lw["t"], y=lw["pipeline_s"], mode="lines+markers",
                           line=dict(color=ui.SERIES[0], width=2), marker=dict(size=8, line=dict(color=ui.SURFACE, width=2)),
                           hovertemplate="%{x}<br>total %{y:.2f} s<extra></extra>"),
                go.Scatter(name="CICFlowMeter conversion", x=lw["t"], y=lw["conversion_s"], mode="lines+markers",
                           line=dict(color=ui.SERIES[1], width=2), marker=dict(size=8, line=dict(color=ui.SURFACE, width=2)),
                           hovertemplate="%{x}<br>conversion %{y:.2f} s<extra></extra>"),
            ])
            fig.update_layout(title="Detection latency per window", yaxis_title="seconds", xaxis_title="window start (UTC)",
                              hovermode="x unified")
            fig.update_xaxes(type="category", nticks=8)
            fig.update_yaxes(rangemode="tozero")
            show(fig)


def history(ov):
    w = ui.df(ov["windows"])
    with st.expander(f"Capture window history (latest {len(w)} windows) · pending PCAPs: {len(ov.get('pending') or [])}",
                     expanded=False):
        if w.empty:
            ui.empty("No capture windows yet.")
            return
        t = pd.DataFrame({
            "Window": w["id"], "PCAP": w["pcap_file"].map(ui.short), "Started (UTC)": w["started_at"].fillna("").str.slice(11, 19),
            "Duration (s)": w["duration_s"], "Packets": w["packets"], "Status": w["status"],
            "CSV": w["csv_file"].map(ui.short), "Flows": w["flows"], "Malicious": w["malicious"], "Alerts": w["alerts"],
            "Conversion (s)": w["conversion_s"], "Prediction (ms)": w["prediction_ms"], "Total (s)": w["pipeline_s"],
            "Next window (s)": w["next_window_s"],
        })
        sel = st.dataframe(t, hide_index=True, width="stretch", height=320, on_select="rerun", selection_mode="single-row",
                           key="hist_table", column_config={
                               "Duration (s)": st.column_config.NumberColumn(format="%.1f"),
                               "Conversion (s)": st.column_config.NumberColumn(format="%.2f"),
                               "Prediction (ms)": st.column_config.NumberColumn(format="%.0f"),
                               "Total (s)": st.column_config.NumberColumn(format="%.2f", help="window end → results stored"),
                               "PCAP": st.column_config.TextColumn(help="Select a row for the full file names"),
                           })
        rows = sel.selection.rows if sel and sel.selection else []
        if rows:
            r = w.iloc[rows[0]]
            st.markdown(f"**Window {int(r['id'])}** · PCAP `{r['pcap_file']}` · CSV `{r['csv_file'] or '—'}` · "
                        f"interface {r['interface'] or '—'} · {r['started_at'] or '—'} → {r['ended_at'] or '—'} · "
                        f"{ui.fmt_int(r['bytes'])} bytes" + (f" · error: {r['error']}" if r["error"] else ""))
        else:
            st.caption("Select a row for full file names and details.")


@st.fragment(run_every=_interval())
def live():
    ov, mode = api.monitoring_overview(WINDOWS)
    ui.mode_banner(mode)
    simulator_slot, running, online = toolbar(ov, mode)
    if not ov:
        ui.empty("No monitoring data available.")
        return
    runs = ov.get("simulations") or []
    active = any(r["status"] in simulator.ACTIVE for r in runs)
    if active != bool(st.session_state.get("sim_active")):   # refresh interval depends on it: full rerun
        st.session_state["sim_active"] = active
        st.rerun()
    if simulator_slot.button("Attack Simulator", icon=":material/science:", width="stretch",
                             disabled=not online or active,
                             help="Run a simulation already active" if active else
                             ("needs the backend" if not online else "Launch a controlled lab traffic Job")):
        simulator.dialog()
    simulator.panel(runs, online)
    stats(ov)
    feed(ov.get("app_ports") or {}, runs)
    st.markdown('<div class="ids-section">Live traffic</div>', unsafe_allow_html=True)
    charts(ov)
    history(ov)


live()

with st.expander("Historical records and dataset replay", expanded=False):
    st.caption("All stored detections by data source, including historical dataset replays (offline mode).")
    h1, h2, h3 = st.columns([1.6, 1.2, 1])
    sources = h1.multiselect("Data source", list(ui.SOURCE_LABELS), default=["pcap", "dataset"],
                             format_func=lambda s: ui.SOURCE_LABELS[s], key="hist_sources")
    hcls = h2.selectbox("Attack class", ["All"] + class_list, key="hist_cls")
    hlimit = h3.number_input("Rows per source", 100, 5000, 500, step=100, key="hist_limit")
    frames = [ui.df(api.detections(limit=int(hlimit), source=s, predicted_class=None if hcls == "All" else hcls)[0])
              for s in sources]
    hd = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    ui.detections_table(hd.sort_values("detected_at", ascending=False) if not hd.empty else hd, height=300)

    st.markdown('<div class="ids-section">Replay a flow CSV (offline mode)</div>', unsafe_allow_html=True)
    ds, _ = api.datasets()
    if ds:
        r1, r2, r3 = st.columns([2.2, 1, 1], vertical_alignment="bottom")
        files = [d["file"] for d in ds["dataset"]] + [d["file"] for d in ds["captured"]]
        fsel = r1.selectbox("Flow CSV", files, key="replay_file")
        mx = r2.number_input("Max rows (sampled if larger)", 100, 100000, 30000, step=1000, key="replay_rows")
        if r3.button("Run detection on file", width="stretch"):
            ok, res = api.write("POST", "/api/detection/run", {"file": fsel, "max_rows": int(mx)})
            if ok:
                st.success(f"{res['flows']} flows classified by {res['model']} ({res['batch_ms']:.0f} ms), "
                           f"{res['malicious']} malicious; source = {ui.SOURCE_LABELS.get(res['source'], res['source'])}")
                st.json(res["classes"])
            else:
                st.error(f"Failed: {res}")
        if st.button("Process pending PCAPs", help="Convert and classify captured PCAPs that were not processed yet"):
            ok, res = api.write("POST", "/api/capture/process", {})
            (st.success if ok else st.error)(f"Processed {len(res['processed'])} file(s)" if ok else f"Failed: {res}")
    else:
        ui.empty("Backend offline: dataset replay needs the backend.")
