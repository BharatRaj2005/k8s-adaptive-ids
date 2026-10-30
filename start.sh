#!/usr/bin/env bash
# Start the backend (FastAPI on 127.0.0.1:8000) and the dashboard (Streamlit on :8501).
#   ./start.sh            start both in the background (logs in logs/)
#   ./start.sh stop       stop both
#   ./start.sh status
set -euo pipefail
cd "$(dirname "$0")"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-8501}"
mkdir -p logs

pid_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

case "${1:-start}" in
  start)
    if pid_alive logs/backend.pid; then echo "backend already running"; else
      nohup .venv/bin/uvicorn src.backend.app:app --host 127.0.0.1 --port "$API_PORT" >> logs/backend.log 2>&1 &
      echo $! > logs/backend.pid; echo "backend  -> http://127.0.0.1:$API_PORT/docs"; fi
    if pid_alive logs/frontend.pid; then echo "frontend already running"; else
      IDS_API_URL="http://127.0.0.1:$API_PORT" nohup .venv/bin/streamlit run frontend/app.py \
        --server.port "$UI_PORT" --server.headless true >> logs/frontend.log 2>&1 &
      echo $! > logs/frontend.pid; echo "frontend -> http://localhost:$UI_PORT"; fi
    ;;
  stop)
    for s in frontend backend; do
      if pid_alive "logs/$s.pid"; then kill "$(cat "logs/$s.pid")" && echo "stopped $s"; fi
      rm -f "logs/$s.pid"
    done
    ;;
  status)
    for s in backend frontend; do pid_alive "logs/$s.pid" && echo "$s running" || echo "$s stopped"; done
    ;;
  *) echo "usage: $0 [start|stop|status]"; exit 1 ;;
esac
