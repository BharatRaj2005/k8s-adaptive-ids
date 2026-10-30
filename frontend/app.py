"""SOC dashboard for the Adaptive IDS & Deception prototype.

    .venv/bin/streamlit run frontend/app.py      (or ./start.sh)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "frontend")):
    if p not in sys.path:
        sys.path.insert(0, p)

import streamlit as st  # noqa: E402

from components import api, ui  # noqa: E402

st.set_page_config(page_title="K8s Adaptive IDS", page_icon="🛡️", layout="wide")
ui.setup_page()

pages = [
    st.Page("views/overview.py", title="Security Overview", icon=":material/dashboard:", default=True),
    st.Page("views/monitoring.py", title="Live Traffic Monitoring", icon=":material/lan:"),
    st.Page("views/classification.py", title="Attack Classification", icon=":material/category:"),
    st.Page("views/deception.py", title="Adaptive Deception", icon=":material/shield:"),
    st.Page("views/capture.py", title="Traffic Capture", icon=":material/radio_button_checked:"),
    st.Page("views/performance.py", title="Model Performance", icon=":material/monitoring:"),
    st.Page("views/kubernetes.py", title="Kubernetes Status", icon=":material/hub:"),
]

with st.sidebar:
    st.markdown("### 🛡️ K8s Adaptive IDS")
    online = api.backend_online()
    st.markdown(ui.badge("Backend online" if online else "Backend offline", "good" if online else "warning"),
                unsafe_allow_html=True)
    st.caption(f"API: {api.API}")
    st.session_state["auto_refresh"] = st.toggle("Auto-refresh (5 s)", value=st.session_state.get("auto_refresh", False))

st.navigation(pages).run()
