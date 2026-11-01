"""Predefined Attack Simulator scenarios and request validation.

A request names a category, a scenario key, a target application and three numbers
(duration, approximate request rate, maximum requests). Everything else comes from
config/settings.yaml (`simulator`) and the application allow-list in config/datagen.yaml.
Nothing in a request becomes a URL, a command or a manifest field directly.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.datagen.plan import load_datagen_config
from src.utils.config import load_config

ALL_APPS = "all"


class ScenarioError(ValueError):
    pass


@dataclass
class SimulationSpec:
    category: str            # recon | benign
    scenario: str            # key in simulator.scenarios.<category>
    label: str
    profile: str             # generator profile (kubernetes/traffic-generator/datagen_generator.py)
    apps: list[str]
    duration_s: int
    rate_per_s: float
    max_requests: int
    env: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def catalog(cfg: dict[str, Any] | None = None, dcfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg, dcfg = cfg or load_config(), dcfg or load_datagen_config()
    s = cfg["simulator"]
    names = {int(k): v for k, v in cfg["classes"].items()}
    benign = cfg["benign_label"]

    def expected(cat: str, v: dict[str, Any]) -> int | None:
        if v.get("class_label") is not None:   # attack scenarios carry their class
            return int(v["class_label"])
        if cat == "recon":
            return 2                            # Node-RED Reconnaissance (dataset class)
        if cat == "benign":
            return benign
        return None

    def scen(cat: str, v: dict[str, Any]) -> dict[str, Any]:
        ec = expected(cat, v)
        return {"label": v["label"], "description": v["description"], "profile": v["profile"],
                "all_apps": bool(v.get("all_apps")), "app": v.get("app"), "class_label": v.get("class_label"),
                "expected_class": ec, "expected_class_name": names.get(ec) if ec is not None else None,
                "defaults": v["defaults"]}

    host = {k: {"label": v["label"], "attack_class": v["class"], "description": v.get("description", ""),
                "confidence": float(v.get("confidence", 0.9)),
                "class_id": next((i for i, n in names.items() if n == v["class"]), None)}
            for k, v in (s.get("host_events") or {}).items()}
    return {
        "categories": {cat: {k: scen(cat, v) for k, v in sc.items()} for cat, sc in s["scenarios"].items()},
        "host_events": host,
        "targets": {a: {"port": c["port"], "namespace": c["namespace"], "service": c["service"]}
                    for a, c in dcfg["apps"].items()},
        "limits": s["limits"], "max_active": s["max_active"], "namespace": s["namespace"],
    }


def _number(name: str, value: Any, bounds: list[float], integer: bool) -> float | int:
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise ScenarioError(f"{name} must be a number")
    if v != v or not bounds[0] <= v <= bounds[1]:
        raise ScenarioError(f"{name} must be between {bounds[0]} and {bounds[1]}")
    return int(round(v)) if integer else round(v, 3)


def build_spec(category: str, scenario: str, target: str, duration_s: Any = None, rate_per_s: Any = None,
               max_requests: Any = None, cfg: dict[str, Any] | None = None,
               dcfg: dict[str, Any] | None = None) -> SimulationSpec:
    cfg, dcfg = cfg or load_config(), dcfg or load_datagen_config()
    s = cfg["simulator"]
    scen = s["scenarios"].get(category, {}).get(scenario) if isinstance(category, str) else None
    if scen is None:
        raise ScenarioError(f"unknown scenario {category}/{scenario}")
    apps = dcfg["apps"]
    pinned = scen.get("app")
    if pinned:                                   # attack scenarios only ever hit their one target app
        if pinned not in apps:
            raise ScenarioError(f"scenario {scenario} pins unknown application {pinned!r}")
        if target not in (ALL_APPS, pinned):
            raise ScenarioError(f"scenario {scenario} can only target {pinned!r}")
        targets = [pinned]
    elif scen.get("all_apps"):
        if target not in (ALL_APPS, *apps):
            raise ScenarioError(f"target {target!r} is not an allowed application")
        targets = list(apps)
    else:
        if target not in apps:
            raise ScenarioError(f"target {target!r} is not an allowed application ({', '.join(apps)})")
        targets = [target]
    d, lim = scen["defaults"], s["limits"]
    duration = _number("duration_s", d["duration_s"] if duration_s is None else duration_s, lim["duration_s"], True)
    rate = _number("rate_per_s", d["rate_per_s"] if rate_per_s is None else rate_per_s, lim["rate_per_s"], False)
    requests = _number("max_requests", d["max_requests"] if max_requests is None else max_requests,
                       lim["max_requests"], True)

    workers = int(scen.get("workers", 1))
    delay = workers / rate                         # per-worker spacing for the requested total rate
    if scen["profile"] == "burst_refresh":         # one burst per period: period = mean burst / rate
        delay = sum(scen["burst"]) / 2 / rate
    jitter = float(scen.get("jitter", 0.0))
    lo, hi = max(0.02, delay * (1 - jitter)), max(0.02, delay * (1 + jitter))
    env = {
        "PROFILE": scen["profile"], "SEED": "0", "TARGET_APPS": ",".join(targets),
        "APP_URLS": ",".join(f"{a}=http://{c['service']}.{c['namespace']}.svc.cluster.local:{c['port']}"
                             for a, c in apps.items()),
        "DELAY_MIN": f"{lo:.3f}", "DELAY_MAX": f"{hi:.3f}", "REQUESTS": str(requests),
        "MAX_SECONDS": str(duration), "WORKERS": str(workers),
    }
    if "reconnect" in scen:
        env["RECONNECT_MIN"], env["RECONNECT_MAX"] = map(str, scen["reconnect"])
    if "burst" in scen:
        env["BURST_MIN"], env["BURST_MAX"] = map(str, scen["burst"])
    return SimulationSpec(category, scenario, scen["label"], scen["profile"], targets, duration, rate, requests, env)
