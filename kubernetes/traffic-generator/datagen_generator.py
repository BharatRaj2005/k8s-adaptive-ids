"""Traffic generator v2 for dataset generation (runs as one Job per capture session).

PROFILE selects one benign profile or one scanner implementation:

  benign  browse, poller, keepalive_client, burst_refresh, asset_loader, api_consumer
  recon   seq_wordlist, shuffled_jitter, keepalive_scanner, threaded_parallel, head_crawler, multi_app_sweep
  attack  nodered_inject, grafana_traversal, influx_authprobe

Scanners only send GET/HEAD/OPTIONS requests for paths (path enumeration). The attack profiles
reproduce the request *shape* of three application CVEs without performing them: every request
carries the header X-IDS-Simulation: 1, write-API bodies are non-deployable marker objects (the
server rejects them, nothing is deployed and no code runs), path-traversal targets are marker
filenames (never a real file or secret) and auth headers carry a marker token (never a real or
forged credential). No request carries a real payload, credential or query against an application.

Only the applications in APP_URLS (name=url, comma separated) can be contacted, and
the namespace NetworkPolicy blocks all other egress. Limits are enforced here as well
as by the host-side launcher. Every TCP connection is logged with its local port and
every request with its connection id, as JSON lines on stdout. That log is the
ground truth used to label the captured flows.
"""
import http.client
import itertools
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

# hard limits, independent of the launcher
DELAY_FLOOR = 0.02
REQUEST_CAP = 1000
SECONDS_CAP = 600
WORKER_CAP = 8
TIMEOUT = 5

PROFILE = os.environ.get("PROFILE", "")
SESSION = os.environ.get("SESSION_ID", "local")
SEED = int(os.environ.get("SEED", "1"))
DELAY_MIN = float(os.environ.get("DELAY_MIN", "1.0"))
DELAY_MAX = float(os.environ.get("DELAY_MAX", str(DELAY_MIN)))
REQUESTS = int(os.environ.get("REQUESTS", "100"))
MAX_SECONDS = float(os.environ.get("MAX_SECONDS", "300"))
WORKERS = int(os.environ.get("WORKERS", "1"))
RECONNECT_MIN = int(os.environ.get("RECONNECT_MIN", "10"))
RECONNECT_MAX = int(os.environ.get("RECONNECT_MAX", "30"))
BURST_MIN = int(os.environ.get("BURST_MIN", "3"))
BURST_MAX = int(os.environ.get("BURST_MAX", "6"))
APPS = {k.strip(): urlsplit(v.strip()) for k, v in
        (item.split("=", 1) for item in os.environ.get("APP_URLS", "").split(",") if "=" in item)}
TARGET_APPS = [a.strip() for a in os.environ.get("TARGET_APPS", "").split(",") if a.strip()]

# --- benign request sets (all return 2xx/3xx on the lab apps, checked 2026-10-31) -------------
PAGES = {
    "nodered": ["/", "/red/style.min.css", "/vendor/vendor.js", "/red/red.min.js", "/locales/editor", "/settings",
                "/theme", "/plugins", "/nodes", "/icons", "/flows", "/red/keymap.json", "/red/images/node-red.svg",
                "/favicon.ico"],
    "grafana": ["/login", "/public/img/grafana_icon.svg", "/public/img/fav32.png", "/api/health", "/robots.txt"],
    "influxdb": ["/", "/signin", "/health", "/api/v2/setup", "/api/v2", "/ping"],
}
API = {
    "nodered": ["/flows", "/settings", "/diagnostics", "/icons", "/theme", "/flows", "/settings", "/nodes"],
    "grafana": ["/api/health", "/api/health", "/login", "/robots.txt", "/metrics"],
    "influxdb": ["/health", "/ping", "/ready", "/api/v2", "/api/v2/setup", "/health", "/metrics"],
}
POLL = {"nodered": ["/settings", "/"], "grafana": ["/api/health", "/metrics"], "influxdb": ["/health", "/ping", "/metrics"]}

# --- scanner wordlists (paths only) ------------------------------------------------------------
GENERIC = [
    "/", "/admin", "/administrator", "/login", "/auth/login", "/auth/token", "/api", "/api/v1", "/api/v2",
    "/api/health", "/status", "/health", "/metrics", "/version", "/info", "/config", "/config.json", "/env",
    "/.env", "/.git/HEAD", "/.git/config", "/backup", "/backup.zip", "/wp-admin", "/wp-login.php", "/phpinfo.php",
    "/server-status", "/console", "/manager/html", "/actuator", "/actuator/env", "/swagger", "/swagger-ui.html",
    "/graphql", "/robots.txt", "/sitemap.xml", "/upload", "/debug", "/test", "/old", "/dev", "/private",
]
SPECIFIC = {
    "nodered": ["/settings", "/settings/user", "/flows", "/flow", "/nodes", "/nodes/messages", "/icons",
                "/library/flows", "/context/global", "/diagnostics", "/plugins", "/red/keymap.json", "/locales/editor",
                "/theme", "/debug/view/view.html", "/uibuilder", "/ui", "/dashboard", "/worldmap", "/node-red", "/red",
                "/vendor/vendor.js"],
    "grafana": ["/api/frontend/settings", "/api/search", "/api/dashboards/home", "/api/datasources", "/api/org",
                "/api/user", "/api/users", "/api/teams/search", "/api/folders", "/api/alerts", "/api/annotations",
                "/api/playlists", "/api/plugins", "/api/snapshots", "/api/admin/stats", "/api/serviceaccounts/search",
                "/api/library-elements", "/explore", "/dashboards", "/alerting/list", "/public/build/", "/avatar/0"],
    "influxdb": ["/api/v2/buckets", "/api/v2/orgs", "/api/v2/users", "/api/v2/authorizations", "/api/v2/me",
                 "/api/v2/dashboards", "/api/v2/tasks", "/api/v2/scrapers", "/api/v2/variables", "/api/v2/telegrafs",
                 "/api/v2/labels", "/api/v2/flags", "/api/v2/config", "/api/v2/checks", "/api/v2/sources",
                 "/api/v2/backup/metadata", "/debug/vars", "/debug/pprof/", "/query", "/write", "/signin", "/ready"],
}
SUFFIXES = ["", "/", ".bak", ".old", ".json", ".txt", "~"]
CRAWL_CHILDREN = ["/index.html", "/config", "/admin", "/api", "/login", "/static", "/backup", "/v1", "/list"]
USER_AGENTS = ["Mozilla/5.0 (X11; Linux x86_64)", "curl/8.5.0", "python-requests/2.32", "Go-http-client/1.1",
               "Wget/1.21", "dirscan/0.9"]

# --- attack-characteristic request sets (non-destructive; marker requests only) ----------------
# Each attack profile reproduces the request SHAPE of an application CVE. Paths, bodies and tokens
# are fixed constants here (never built from input), every request carries SIM_HEADER, and none can
# change application state, run code or read a secret - see the per-profile guarantees below.
SIM_HEADER = {"X-IDS-Simulation": "1"}
SIM_MARKER = json.dumps({"ids_marker": "simulation", "note": "non-destructive lab traffic"}).encode()
SIM_TOKEN = {"Authorization": "Bearer ids-sim-marker"}
# class 3 Node-RED RCE: POST/PUT to the admin write-API. SIM_MARKER is not a Node-RED flow or
# settings object, so every request is rejected (400/404/405); nothing is deployed and no function
# node runs. (/nodes is deliberately excluded - a POST there would install an npm module.)
INJECT_ENDPOINTS = [("POST", "/flows"), ("POST", "/flow"), ("PUT", "/settings"), ("POST", "/flows")]
# class 5 CVE-2021-43798: Grafana plugin path traversal. The traversal target is a marker filename,
# never a real path such as /etc/passwd or a key file, so it resolves to nothing (400/404).
TRAVERSAL_PLUGINS = ["alertlist", "graph", "table", "text", "piechart"]
TRAVERSAL_MARKER = "ids-sim-marker.txt"
TRAVERSAL_PATHS = [f"/public/plugins/{p}/{'..%2f' * d}{TRAVERSAL_MARKER}"
                   for p in TRAVERSAL_PLUGINS for d in (3, 5, 7, 9, 11)]
# class 6 CVE-2019-20933: InfluxDB auth-bypass probes. SIM_TOKEN is a marker, not a real or forged
# credential, and the endpoints read and write nothing with it (401).
AUTHPROBE_ENDPOINTS = [("POST", "/query"), ("GET", "/api/v2"), ("GET", "/api/v2/buckets"),
                       ("GET", "/debug/vars"), ("GET", "/api/v2/me")]
# class 1 CVE-2020-13379: Grafana unauthenticated avatar SSRF. The SSRF target is a guaranteed
# non-resolvable marker host (RFC 6761 .invalid) and a loopback marker, so no internal service is
# ever reached - the request shape is attack-characteristic but it cannot pull any real resource.
SSRF_TARGETS = ["http://ids-sim-marker.invalid/", "http://ids-sim-marker.invalid:80/latest/meta-data",
                "http://127.0.0.1:1/ids-sim-marker"]
SSRF_PATHS = [f"/avatar/{quote(t, safe='')}" for t in SSRF_TARGETS] + ["/avatar/ids-sim-marker"]

_lock = threading.Lock()
_conn_ids = itertools.count(1)
_count = 0
_errors = 0
_deadline = time.monotonic() + min(MAX_SECONDS, SECONDS_CAP)
UA = f"ids-lab-datagen/{PROFILE}"


def log(**fields):
    fields["ts"] = datetime.now(timezone.utc).isoformat()
    with _lock:
        print(json.dumps(fields), flush=True)


def take() -> bool:
    """Reserve one request of the budget (thread-safe)."""
    global _count
    with _lock:
        if _count >= REQUESTS or time.monotonic() >= _deadline:
            return False
        _count += 1
        return True


def remaining() -> bool:
    return _count < REQUESTS and time.monotonic() < _deadline


def pause(rng, lo, hi):
    time.sleep(max(DELAY_FLOOR, rng.uniform(lo, hi)))


class Conn:
    """One HTTP connection; logs open (with local port), every request and close."""

    def __init__(self, app, keepalive=False, user_agent=None):
        if app not in TARGET_APPS:
            raise ValueError(f"application not allowed: {app}")
        u = APPS[app]
        self.app, self.host, self.port = app, u.hostname, u.port or 80
        self.keepalive, self.ua = keepalive, user_agent or UA
        self.http, self.cid, self.served = None, None, 0

    def _open(self):
        self.http = http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT)
        self.http.connect()
        self.cid = next(_conn_ids)
        self.served = 0
        log(ev="conn_open", cid=self.cid, app=self.app, dst=f"{self.host}:{self.port}",
            peer=self.http.sock.getpeername()[0], lport=self.http.sock.getsockname()[1])

    def close(self):
        if self.http is not None:
            self.http.close()
            log(ev="conn_close", cid=self.cid, app=self.app, requests=self.served)
        self.http = None

    def request(self, method, path, headers=None, body=None, retry=True):
        global _errors
        try:
            if self.http is None:
                self._open()
        except OSError as e:
            with _lock:
                _errors += 1
            log(ev="conn_error", app=self.app, error=str(e))
            self.http = None
            return None
        hdrs = {"User-Agent": self.ua, **(headers or {})}
        if not self.keepalive:
            hdrs["Connection"] = "close"
        t0 = time.monotonic()
        try:
            self.http.request(method, path, body=body, headers=hdrs)
            resp = self.http.getresponse()
            rbody = resp.read()
            status, will_close = resp.status, resp.will_close
        except (http.client.HTTPException, OSError) as e:
            stale = self.keepalive and self.served > 0
            self.close()
            if stale and retry:           # server closed an idle keep-alive connection
                return self.request(method, path, headers, body, retry=False)
            with _lock:
                _errors += 1
            log(ev="req", cid=self.cid, app=self.app, method=method, path=path, error=str(e))
            return None
        self.served += 1
        log(ev="req", cid=self.cid, app=self.app, method=method, path=path, status=status,
            bytes=len(rbody), sent=len(body or b""), ms=round((time.monotonic() - t0) * 1000, 1))
        if will_close or not self.keepalive:
            self.close()
        return status


def once(app, method, path, headers=None, body=None, user_agent=None):
    return Conn(app, keepalive=False, user_agent=user_agent).request(method, path, headers, body)


# --- benign profiles ---------------------------------------------------------------------------
def browse(rng):
    """A user opening pages (page + a few assets), new connection per request, think time between pages."""
    while remaining():
        app = rng.choice(TARGET_APPS)
        page = [PAGES[app][0]] + rng.sample(PAGES[app][1:], rng.randint(0, 3))
        for path in page:
            if not take():
                return
            r = rng.random()
            if r < 0.1:
                once(app, "HEAD", path)
            elif r < 0.3:
                once(app, "GET", path, {"If-Modified-Since": "Sat, 31 Oct 2026 00:00:00 GMT"})
            else:
                once(app, "GET", path)
            time.sleep(rng.uniform(0.05, 0.3))
        pause(rng, DELAY_MIN, DELAY_MAX)


def poller(rng):
    """Health/metrics poller at a near-fixed interval, every target app per tick."""
    while remaining():
        for app in TARGET_APPS:
            if not take():
                return
            path = rng.choice(POLL[app])
            once(app, "HEAD" if path == "/ping" and rng.random() < 0.5 else "GET", path)
        pause(rng, DELAY_MIN, DELAY_MAX)


def keepalive_client(rng):
    """API client with one persistent connection per app, closed after a number of requests."""
    conns = {a: Conn(a, keepalive=True) for a in TARGET_APPS}
    budget = {a: rng.randint(RECONNECT_MIN, RECONNECT_MAX) for a in TARGET_APPS}
    while take():
        app = rng.choice(TARGET_APPS)
        conns[app].request("GET", rng.choice(API[app]))
        if conns[app].served >= budget[app]:
            conns[app].close()
            budget[app] = rng.randint(RECONNECT_MIN, RECONNECT_MAX)
        pause(rng, DELAY_MIN, DELAY_MAX)
    for c in conns.values():
        c.close()


def burst_refresh(rng):
    """Dashboard refresh: a burst of parallel requests every period, then quiet."""
    with ThreadPoolExecutor(max_workers=max(1, WORKERS)) as pool:
        while remaining():
            app = rng.choice(TARGET_APPS)
            jobs = []
            for _ in range(rng.randint(BURST_MIN, BURST_MAX)):
                if not take():
                    break
                jobs.append(pool.submit(once, app, "GET", rng.choice(API[app] + PAGES[app][:3])))
            for j in jobs:
                j.result()
            pause(rng, DELAY_MIN, DELAY_MAX)


def asset_loader(rng):
    """Browser-like full page loads: up to WORKERS parallel keep-alive connections share the assets."""
    while remaining():
        app = rng.choice(TARGET_APPS)
        conns = [Conn(app, keepalive=True) for _ in range(max(1, min(WORKERS, 6)))]
        assets = PAGES[app][:]
        first, rest = assets[0], assets[1:]
        rng.shuffle(rest)
        if take():
            conns[0].request("GET", first)

        def fetch(i):
            for path in rest[i::len(conns)]:
                if not take():
                    return
                conns[i].request("GET", path)

        with ThreadPoolExecutor(max_workers=len(conns)) as pool:
            list(pool.map(fetch, range(len(conns))))
        for c in conns:
            c.close()
        pause(rng, DELAY_MIN, DELAY_MAX)


def api_consumer(rng):
    """High-volume legitimate client: valid endpoints only, new connection per request."""
    while take():
        app = rng.choice(TARGET_APPS)
        once(app, "GET", rng.choice(API[app]))
        pause(rng, DELAY_MIN, DELAY_MAX)


# --- scanner implementations -------------------------------------------------------------------
def wordlist(app):
    return GENERIC + [p for p in SPECIFIC[app] if p not in GENERIC]


def seq_wordlist(rng):
    """Fixed-order wordlist, fixed spacing, new connection per request (the original lab scanner)."""
    app = TARGET_APPS[0]
    paths = wordlist(app)
    i = 0
    while take():
        path = paths[i % len(paths)] + (f"?probe={i}" if i >= len(paths) else "")
        once(app, "HEAD" if i % 7 == 0 else "GET", path)
        i += 1
        time.sleep(max(DELAY_FLOOR, DELAY_MIN))


def shuffled_jitter(rng):
    """Shuffled wordlist x suffix variants, random spacing, random method and user agent per request."""
    cands = [(a, p + s) for a in TARGET_APPS for p in wordlist(a) for s in SUFFIXES]
    rng.shuffle(cands)
    for app, path in itertools.cycle(cands):
        if not take():
            return
        method = rng.choices(["GET", "HEAD", "OPTIONS"], weights=[7, 2, 1])[0]
        once(app, method, path, user_agent=rng.choice(USER_AGENTS))
        pause(rng, DELAY_MIN, DELAY_MAX)


def keepalive_scanner(rng):
    """Many probes over one persistent connection, reconnecting after a random number of probes."""
    app = TARGET_APPS[0]
    paths = SPECIFIC[app] + [p for p in GENERIC if p not in SPECIFIC[app]]
    conn, budget = Conn(app, keepalive=True), rng.randint(RECONNECT_MIN, RECONNECT_MAX)
    for path in itertools.cycle(paths):
        if not take():
            break
        conn.request("GET", path)
        if conn.served >= budget:
            conn.close()
            budget = rng.randint(RECONNECT_MIN, RECONNECT_MAX)
        pause(rng, DELAY_MIN, DELAY_MAX)
    conn.close()


def threaded_parallel(rng):
    """WORKERS concurrent workers draining a shared shuffled queue, new connection per request."""
    cands = [(a, p) for a in TARGET_APPS for p in wordlist(a)]
    rng.shuffle(cands)
    queue = itertools.cycle(cands)
    qlock = threading.Lock()

    def worker(w):
        wrng = random.Random(SEED * 100 + w)
        while take():
            with qlock:
                app, path = next(queue)
            once(app, "GET", path)
            pause(wrng, DELAY_MIN, DELAY_MAX)

    with ThreadPoolExecutor(max_workers=max(1, WORKERS)) as pool:
        list(pool.map(worker, range(max(1, WORKERS))))


def head_crawler(rng):
    """HEAD-only breadth-first crawl: children are tried below every path that did not return 404."""
    app = TARGET_APPS[0]
    frontier = [p for p in wordlist(app) if p.count("/") == 1]
    rng.shuffle(frontier)
    seen = set()
    while frontier and take():
        path = frontier.pop(0)
        seen.add(path)
        status = once(app, "HEAD", path)
        if status is not None and status != 404 and path.count("/") < 3:
            frontier += [path.rstrip("/") + c for c in CRAWL_CHILDREN if path.rstrip("/") + c not in seen]
        if not frontier:
            frontier = [p + "/" for p in wordlist(app) if p + "/" not in seen]
        pause(rng, DELAY_MIN, DELAY_MAX)


def multi_app_sweep(rng):
    """Breadth across applications: every path is tried on every target app before the next one."""
    paths = list(dict.fromkeys(GENERIC + [p for a in TARGET_APPS for p in SPECIFIC[a]]))
    for i, path in enumerate(itertools.cycle(paths)):
        for app in TARGET_APPS:
            if not take():
                return
            once(app, "GET" if (i + len(app)) % 2 else "HEAD", path)
            pause(rng, DELAY_MIN, DELAY_MAX)


# --- attack-characteristic profiles (see the request sets above for the safety guarantees) -----
def nodered_inject(rng):
    """Node-RED RCE shape (class 3): marker writes to the admin flow API, rejected, nothing deployed."""
    app = TARGET_APPS[0]
    i = 0
    while take():
        method, path = INJECT_ENDPOINTS[i % len(INJECT_ENDPOINTS)]
        body = None if path == "/settings" else SIM_MARKER
        hdrs = {**SIM_HEADER, "Content-Type": "application/json"} if body else dict(SIM_HEADER)
        once(app, method, path, headers=hdrs, body=body)
        i += 1
        pause(rng, DELAY_MIN, DELAY_MAX)


def grafana_traversal(rng):
    """CVE-2021-43798 shape (class 5): plugin path traversal to a marker filename (resolves to nothing)."""
    app = TARGET_APPS[0]
    paths = TRAVERSAL_PATHS[:]
    rng.shuffle(paths)
    for path in itertools.cycle(paths):
        if not take():
            return
        once(app, "GET", path, headers=SIM_HEADER)
        pause(rng, DELAY_MIN, DELAY_MAX)


def influx_authprobe(rng):
    """CVE-2019-20933 shape (class 6): auth-bypass probes with a marker token (reads/writes nothing)."""
    app = TARGET_APPS[0]
    i = 0
    while take():
        method, path = AUTHPROBE_ENDPOINTS[i % len(AUTHPROBE_ENDPOINTS)]
        body = SIM_MARKER if method == "POST" else None
        hdrs = {**SIM_HEADER, **SIM_TOKEN}
        if body:
            hdrs["Content-Type"] = "application/json"
        once(app, method, path, headers=hdrs, body=body)
        i += 1
        pause(rng, DELAY_MIN, DELAY_MAX)


def grafana_ssrf(rng):
    """CVE-2020-13379 shape (class 1): Grafana avatar SSRF requests to a non-resolvable marker target.
    Non-destructive: the SSRF target is .invalid / loopback:1, so Grafana reaches no internal service."""
    app = TARGET_APPS[0]
    i = 0
    while take():
        once(app, "GET", SSRF_PATHS[i % len(SSRF_PATHS)], headers=SIM_HEADER)
        i += 1
        pause(rng, DELAY_MIN, DELAY_MAX)


BENIGN = {f.__name__: f for f in (browse, poller, keepalive_client, burst_refresh, asset_loader, api_consumer)}
RECON = {f.__name__: f for f in (seq_wordlist, shuffled_jitter, keepalive_scanner, threaded_parallel, head_crawler,
                                 multi_app_sweep)}
ATTACK = {f.__name__: f for f in (nodered_inject, grafana_traversal, influx_authprobe, grafana_ssrf)}


def validate():
    errors = []
    if PROFILE not in BENIGN and PROFILE not in RECON and PROFILE not in ATTACK:
        errors.append(f"unknown PROFILE {PROFILE!r}")
    if not TARGET_APPS or any(a not in APPS or a not in PAGES for a in TARGET_APPS):
        errors.append(f"TARGET_APPS {TARGET_APPS} must be known apps listed in APP_URLS")
    if DELAY_MIN < DELAY_FLOOR or DELAY_MAX < DELAY_MIN:
        errors.append(f"delay range {DELAY_MIN}-{DELAY_MAX} invalid (floor {DELAY_FLOOR})")
    if not 0 < REQUESTS <= REQUEST_CAP:
        errors.append(f"REQUESTS {REQUESTS} outside 1..{REQUEST_CAP}")
    if not 0 < MAX_SECONDS <= SECONDS_CAP:
        errors.append(f"MAX_SECONDS {MAX_SECONDS} outside 1..{SECONDS_CAP}")
    if not 1 <= WORKERS <= WORKER_CAP:
        errors.append(f"WORKERS {WORKERS} outside 1..{WORKER_CAP}")
    return errors


def main():
    errors = validate()
    if errors:
        sys.exit("; ".join(errors))
    rng = random.Random(SEED)
    kind = "benign" if PROFILE in BENIGN else "recon" if PROFILE in RECON else "attack"
    log(ev="start", session=SESSION, profile=PROFILE, kind=kind, seed=SEED, apps=TARGET_APPS, requests=REQUESTS,
        delay=[DELAY_MIN, DELAY_MAX], workers=WORKERS)
    (BENIGN.get(PROFILE) or RECON.get(PROFILE) or ATTACK[PROFILE])(rng)
    log(ev="end", session=SESSION, requests=_count, errors=_errors)


if __name__ == "__main__":
    main()
