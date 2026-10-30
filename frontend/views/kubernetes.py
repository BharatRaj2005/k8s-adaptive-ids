import pandas as pd
import streamlit as st

from components import api, ui

st.title("Kubernetes Status")
st.caption("Read through the least-privilege ids-controller service account.")


@st.fragment(run_every="10s" if st.session_state.get("auto_refresh") else None)
def body():
    k, mode = api.k8s_status()
    ui.mode_banner(mode)
    if not k or not k.get("connected"):
        st.markdown(ui.badge("Kubernetes not connected", "critical"), unsafe_allow_html=True)
        st.caption((k or {}).get("error", ""))
        st.info("Stored detections and deception records remain available on the other pages.")
        return
    st.markdown(ui.badge("Connected", "good") + "".join(
        ui.badge(f"node {n['name']} {'Ready' if n['ready'] == 'True' else 'NotReady'} · {n['version']}",
                 "good" if n["ready"] == "True" else "critical") for n in k["nodes"]), unsafe_allow_html=True)
    ns = k["namespaces"]
    ui.card_row([ui.card(name, e.get("status", "error"),
                         f"{sum(p['ready'] for p in e.get('pods', []))}/{len(e.get('pods', []))} pods ready")
                 for name, e in ns.items()])

    def pods(name, title, sel=None):
        st.subheader(title)
        rows = [p for p in ns.get(name, {}).get("pods", []) if sel is None or sel(p)]
        if not rows:
            ui.empty("None.")
            return
        st.dataframe(pd.DataFrame([{"Pod": p["name"], "Phase": p["phase"], "Ready": "✓" if p["ready"] else "✕",
                                    "IP": p["ip"], "Restarts": p["restarts"], "Started": (p["started"] or "")[:19]}
                                   for p in rows]), hide_index=True, width="stretch")

    c1, c2 = st.columns(2)
    with c1:
        pods("target-apps", "Target application pods")
    with c2:
        pods("ids-traffic", "Traffic generator", lambda p: p["labels"].get("app") == "traffic-generator")
    c3, c4 = st.columns(2)
    with c3:
        pods("ids-deception", "Active decoy pods", lambda p: p["labels"].get("app.kubernetes.io/component") == "decoy")
    with c4:
        st.subheader("Decoy services")
        svcs = ns.get("ids-deception", {}).get("services", [])
        if svcs:
            st.dataframe(pd.DataFrame([{"Service": s["name"], "Type": s["type"], "Cluster IP": s["cluster_ip"],
                                        "Ports": ", ".join(map(str, s["ports"]))} for s in svcs]),
                         hide_index=True, width="stretch")
        else:
            ui.empty("No decoy services.")
    st.subheader("Recent Kubernetes events")
    evs = [dict(e, namespace=n) for n, e2 in ns.items() for e in e2.get("events", [])]
    if evs:
        e = pd.DataFrame(evs).sort_values("time", ascending=False)
        st.dataframe(e[["time", "namespace", "type", "reason", "object", "message"]], hide_index=True,
                     width="stretch", height=360)
    else:
        ui.empty("No recent events.")


body()
