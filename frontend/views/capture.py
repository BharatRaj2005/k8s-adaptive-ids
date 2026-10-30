import pandas as pd
import streamlit as st

from components import api, ui

st.title("Traffic Capture")
st.caption("tcpdump on cni0 → PCAP window → CICFlowMeter CSV → per-flow model + flow-burst detector → SQLite. "
           "File-based processing: results lag by at least one window.")

c1, c2, c3, c4 = st.columns([1, 1, 1, 1.4])
windows = c4.number_input("Windows (0 = until stopped)", 0, 10000, 0)
if c1.button("Start capture", type="primary", width="stretch"):
    ok, res = api.write("POST", "/api/capture/start", {"windows": int(windows) or None, "process": True})
    (st.success if ok else st.error)("Capture started" if ok else f"Failed: {res}")
if c2.button("Stop capture", width="stretch"):
    ok, res = api.write("POST", "/api/capture/stop")
    (st.success if ok else st.error)("Capture stopped" if ok else f"Failed: {res}")
if c3.button("Process pending PCAPs", width="stretch"):
    ok, res = api.write("POST", "/api/capture/process", {})
    (st.success if ok else st.error)(f"Processed {len(res['processed'])} file(s)" if ok else f"Failed: {res}")


@st.fragment(run_every="3s" if st.session_state.get("auto_refresh") else None)
def body():
    st_, mode = api.capture_status()
    ui.mode_banner(mode)
    svc = (st_ or {}).get("service", {})
    last = svc.get("last_window") or {}
    lr = svc.get("last_result") or {}
    conv = lr.get("conversion") or {}
    running = svc.get("running")
    st.markdown(ui.badge(f"Capture {svc.get('status', 'unknown')}", "good" if running else "neutral")
                + ui.badge(f"Interface {svc.get('interface', '—')}", "neutral"), unsafe_allow_html=True)
    ui.card_row([
        ui.card("Current window", f"{svc.get('current_window_s', '—')} s", "adaptive: 5 / 10 / 30 s by packet rate"),
        ui.card("Windows captured", ui.fmt_int(svc.get("windows")), f"processed {svc.get('processed', 0)}, failed {svc.get('failed', 0)}"),
        ui.card("Last window packets", ui.fmt_int(last.get("packets")), f"{last.get('duration_s', 0):.1f} s" if last else ""),
        ui.card("Pending PCAPs", ui.fmt_int(len((st_ or {}).get("pending", []))), "not yet classified"),
    ])
    st.write("")
    ui.card_row([
        ui.card("Last PCAP", (last.get("pcap") or "—").rsplit("/", 1)[-1][-28:], "captures/pcap/"),
        ui.card("CICFlowMeter conversion", conv.get("status", "—"),
                f"{conv.get('flows', 0)} flows in {conv.get('seconds', 0):.2f} s" if conv else ""),
        ui.card("Generated CSV", (conv.get("csv") or "—").rsplit("/", 1)[-1][-28:], "captures/flows/"),
        ui.card("Classification", lr.get("status", "—"),
                f"{lr.get('malicious', 0)} malicious · {lr.get('flow_bursts', 0)} bursts · pipeline {lr.get('pipeline_s', 0):.2f} s"
                if lr.get("status") == "classified" else (lr.get("error") or "")),
    ])
    st.subheader("Capture windows")
    caps = ui.df(api.captures(100)[0])
    if caps.empty:
        ui.empty("No capture windows yet.")
    else:
        st.dataframe(pd.DataFrame({
            "PCAP": caps["pcap_file"], "Started (UTC)": caps["started_at"].fillna("").str.slice(11, 19),
            "Duration (s)": caps["duration_s"], "Packets": caps["packets"], "Status": caps["status"],
            "CSV": caps["csv_file"].fillna(""), "Flows": caps["flows"], "Conversion (s)": caps["conversion_s"],
            "Prediction (ms)": caps["prediction_ms"], "Pipeline (s)": caps["pipeline_s"],
            "Next window (s)": caps["next_window_s"], "Error": caps["error"].fillna(""),
        }), hide_index=True, width="stretch", height=380)


body()

st.subheader("Offline mode: replay dataset flows")
ds, _ = api.datasets()
if ds:
    files = [d["file"] for d in ds["dataset"]] + [d["file"] for d in ds["captured"]]
    f = st.selectbox("Flow CSV", files)
    mx = st.number_input("Max rows (sampled if larger)", 100, 100000, 30000, step=1000)
    if st.button("Run detection on file"):
        ok, res = api.write("POST", "/api/detection/run", {"file": f, "max_rows": int(mx)})
        if ok:
            st.success(f"{res['flows']} flows classified by {res['model']} ({res['batch_ms']:.0f} ms), "
                       f"{res['malicious']} malicious; source = {ui.SOURCE_LABELS.get(res['source'], res['source'])}")
            st.json(res["classes"])
            if res.get("agreement_with_file_labels") is not None:
                st.caption(f"Agreement with the file's labels: {res['agreement_with_file_labels']:.3f} — {res['note']}.")
        else:
            st.error(f"Failed: {res}")
else:
    ui.empty("Backend offline: dataset replay needs the backend.")
