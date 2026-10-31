"""Lab traffic generator (runs inside the ids-traffic namespace).

Modes (env MODE):
  benign - endless low-rate browsing/health-check traffic against the lab services
  recon  - a bounded, low-rate HTTP path enumeration against Node-RED, resembling
           the reconnaissance scenario of the training dataset (no exploits)
  decoy  - a bounded visit of the decoy services listed in DECOY_URLS

Only the hosts in TARGETS are contacted; the namespace NetworkPolicy additionally
blocks all other egress. Every request is logged to stdout as one JSON line, which
serves as ground truth for the captured windows.
"""
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

MODE = os.environ.get("MODE", "benign")
NODERED = os.environ.get("NODERED_URL", "http://nodered.target-apps.svc.cluster.local:1880")
GRAFANA = os.environ.get("GRAFANA_URL", "http://grafana.target-apps.svc.cluster.local:3000")
INFLUXDB = os.environ.get("INFLUXDB_URL", "http://influxdb.target-apps.svc.cluster.local:8086")
DECOY_URLS = [u.strip().rstrip("/") for u in os.environ.get("DECOY_URLS", "").split(",") if u.strip()]
TARGETS = (NODERED, GRAFANA, INFLUXDB, *DECOY_URLS)
MIN_DELAY = float(os.environ.get("MIN_DELAY", "1.0"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "4.0"))
RECON_REQUESTS = int(os.environ.get("RECON_REQUESTS", "300"))
RECON_DELAY = float(os.environ.get("RECON_DELAY", "0.2"))
# RECON_TARGET=grafana runs a second, differently built scan (other paths, other app,
# HEAD/GET mix of its own) used to test detection of a scanner the model never saw.
RECON_TARGET = os.environ.get("RECON_TARGET", "nodered")
TIMEOUT = 5

BENIGN_REQUESTS = [
    (NODERED, "/"), (NODERED, "/flows"), (NODERED, "/settings"), (NODERED, "/red/images/node-red.svg"),
    (GRAFANA, "/api/health"), (GRAFANA, "/login"), (GRAFANA, "/public/img/grafana_icon.svg"),
    (INFLUXDB, "/health"), (INFLUXDB, "/ping"), (INFLUXDB, "/api/v2/setup"),
]

RECON_PATHS = [
    "/", "/admin", "/administrator", "/login", "/auth/login", "/auth/token", "/settings", "/settings/user",
    "/flows", "/flow", "/nodes", "/nodes/messages", "/icons", "/library/flows", "/context/global",
    "/diagnostics", "/plugins", "/red/keymap.json", "/locales/editor", "/theme", "/debug/view/view.html",
    "/api", "/api/v1", "/api/v2", "/api/health", "/status", "/health", "/metrics", "/version", "/info",
    "/config", "/config.json", "/env", "/.env", "/.git/HEAD", "/.git/config", "/backup", "/backup.zip",
    "/wp-admin", "/wp-login.php", "/phpinfo.php", "/server-status", "/console", "/manager/html",
    "/actuator", "/actuator/env", "/swagger", "/swagger-ui.html", "/graphql", "/robots.txt", "/sitemap.xml",
    "/uibuilder", "/ui", "/dashboard", "/worldmap", "/node-red", "/red", "/vendor/vendor.js", "/upload",
]


def log(**fields):
    fields["ts"] = datetime.now(timezone.utc).isoformat()
    fields["mode"] = MODE
    print(json.dumps(fields), flush=True)


def request(base, path, method="GET"):
    if base not in TARGETS:
        raise ValueError(f"target not allowed: {base}")
    url = base + path
    req = urllib.request.Request(url, method=method, headers={"User-Agent": f"ids-lab-traffic/{MODE}"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            resp.read(65536)
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError) as e:
        log(url=url, method=method, error=str(e))
        return
    log(url=url, method=method, status=status, ms=round((time.monotonic() - start) * 1000, 1))


def run_benign():
    while True:
        base, path = random.choice(BENIGN_REQUESTS)
        request(base, path)
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


# Documented Grafana HTTP API and UI paths (read-only requests).
GRAFANA_PATHS = [
    "/api/health", "/api/frontend/settings", "/api/search", "/api/dashboards/home", "/api/datasources",
    "/api/org", "/api/user", "/api/users", "/api/teams/search", "/api/folders", "/api/alerts",
    "/api/annotations", "/api/playlists", "/api/plugins", "/api/snapshots", "/api/admin/stats",
    "/api/serviceaccounts/search", "/api/library-elements", "/login", "/explore", "/dashboards",
    "/alerting/list", "/metrics", "/robots.txt", "/public/build/", "/avatar/0",
]


def run_recon():
    base, paths = (GRAFANA, GRAFANA_PATHS) if RECON_TARGET == "grafana" else (NODERED, RECON_PATHS)
    if base == GRAFANA:
        log(event="recon_start", target=base, requests=RECON_REQUESTS)
        for i in range(RECON_REQUESTS):
            path = paths[(i * 7) % len(paths)]
            request(base, path, method="GET" if i % 3 else "HEAD")
            time.sleep(RECON_DELAY)
        log(event="recon_end", target=base)
        return
    log(event="recon_start", target=NODERED, requests=RECON_REQUESTS)
    for i in range(RECON_REQUESTS):
        path = RECON_PATHS[i % len(RECON_PATHS)]
        if i >= len(RECON_PATHS):
            path += f"?probe={i}"
        request(NODERED, path, method="HEAD" if i % 7 == 0 else "GET")
        time.sleep(RECON_DELAY)
    log(event="recon_end", target=NODERED)


def run_decoy():
    """Bounded visit of decoy services (DECOY_URLS), as an attacker following up a scan would."""
    for base in DECOY_URLS:
        for path in RECON_PATHS[:25]:
            request(base, path)
            time.sleep(RECON_DELAY)
        request(base, "/login", method="POST")


if __name__ == "__main__":
    {"benign": run_benign, "recon": run_recon, "decoy": run_decoy}.get(
        MODE, lambda: sys.exit(f"unknown MODE {MODE}"))()
