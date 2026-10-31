"""Session plan for dataset generation (config/datagen.yaml).

Expands the tier tables into concrete sessions (ID, category, profile/scanner, tier,
target applications, seed, generator parameters), validates every session against
the configured limits, and assigns each whole session to a split role.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Any

import yaml

from src.utils.config import PROJECT_ROOT, project_path

DEFAULT_DATAGEN_CONFIG = PROJECT_ROOT / "config" / "datagen.yaml"
BENIGN, RECON = "benign", "recon"
LABELS = {BENIGN: 0, RECON: 2}   # class ids of config/settings.yaml
ROLES = ("train", "val", "test", "heldout_scanner")


class PlanError(ValueError):
    pass


@lru_cache(maxsize=2)
def load_datagen_config(path: str | None = None) -> dict[str, Any]:
    p = path or os.environ.get("IDS_DATAGEN_CONFIG", DEFAULT_DATAGEN_CONFIG)
    with open(p, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def output_dir(dcfg: dict[str, Any]):
    return project_path(dcfg["output_dir"])


@dataclass
class Session:
    session_id: str
    category: str            # benign | recon
    profile: str             # benign profile or scanner implementation
    tier: str
    repeat: int
    index: int
    apps: list[str]
    seed: int
    params: dict[str, Any]
    label: int
    role: str = ""
    env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _apps_for(profile: str, index: int, dcfg: dict[str, Any]) -> list[str]:
    cyc, p = dcfg["plan"]["apps_cycle"], dcfg["plan"]
    if profile in p["all_apps"]:
        return list(cyc)
    if profile in p["two_apps"]:
        return [cyc[index % len(cyc)], cyc[(index + 1) % len(cyc)]]
    return [cyc[index % len(cyc)]]


def generator_env(s: Session, dcfg: dict[str, Any]) -> dict[str, str]:
    prm = s.params
    env = {
        "PROFILE": s.profile, "SESSION_ID": s.session_id, "SEED": str(s.seed),
        "TARGET_APPS": ",".join(s.apps),
        "APP_URLS": ",".join(f"{a}=http://{c['service']}.{c['namespace']}.svc.cluster.local:{c['port']}"
                             for a, c in dcfg["apps"].items()),
        "DELAY_MIN": str(prm["delay"][0]), "DELAY_MAX": str(prm["delay"][1]),
        "REQUESTS": str(prm["requests"]), "MAX_SECONDS": str(dcfg["limits"]["max_session_seconds"]),
        "WORKERS": str(prm.get("workers", 1)),
    }
    if "reconnect" in prm:
        env["RECONNECT_MIN"], env["RECONNECT_MAX"] = map(str, prm["reconnect"])
    if "burst" in prm:
        env["BURST_MIN"], env["BURST_MAX"] = map(str, prm["burst"])
    return env


def validate_session(s: Session, dcfg: dict[str, Any]) -> None:
    lim, prm = dcfg["limits"], s.params
    errors = []
    unknown = [a for a in s.apps if a not in dcfg["apps"]]
    if unknown or not s.apps:
        errors.append(f"applications {unknown or s.apps} are not in the allow-list")
    lo, hi = prm["delay"]
    if lo < lim["min_delay_s"] or hi < lo:
        errors.append(f"delay {prm['delay']} below the floor {lim['min_delay_s']} or inverted")
    if not 0 < prm["requests"] <= lim["max_requests"]:
        errors.append(f"requests {prm['requests']} outside 1..{lim['max_requests']}")
    if not 1 <= prm.get("workers", 1) <= lim["max_workers"]:
        errors.append(f"workers {prm.get('workers')} outside 1..{lim['max_workers']}")
    if errors:
        raise PlanError(f"{s.session_id}: " + "; ".join(errors))


def build_plan(dcfg: dict[str, Any]) -> list[Session]:
    """All sessions in execution order, validated and with split roles assigned."""
    p = dcfg["plan"]
    sessions: list[Session] = []
    idx = 0
    for category, repeats in ((BENIGN, p["benign_repeats"]), (RECON, p["recon_repeats"])):
        for profile, tiers in dcfg["tiers"][category].items():
            extra = tiers.get("extra", {})
            for tier, tparams in tiers.items():
                if tier == "extra":
                    continue
                for rep in range(1, repeats + 1):
                    params = {**extra, **tparams}
                    sid = f"{category}-{profile}-{tier}-r{rep}"
                    s = Session(sid, category, profile, tier, rep, idx, _apps_for(profile, idx, dcfg),
                                p["base_seed"] + idx, params, LABELS[category])
                    validate_session(s, dcfg)
                    s.env = generator_env(s, dcfg)
                    sessions.append(s)
                    idx += 1
    assign_roles(sessions, dcfg)
    return sessions


def assign_roles(sessions: list[Session], dcfg: dict[str, Any]) -> None:
    """Whole sessions only. Rotations make val/test cover different tiers per profile."""
    sp = dcfg["split"]
    for i, prof in enumerate(dict.fromkeys(s.profile for s in sessions if s.category == BENIGN)):
        group = sorted((s for s in sessions if s.profile == prof), key=lambda s: (s.index,))
        tiers = list(dict.fromkeys(s.tier for s in group))
        test_tier = tiers[i % len(tiers)]
        val_tier = tiers[(i + 1) % len(tiers)] if sp.get("benign_val_profiles_even") and i % 2 == 0 else None
        for s in group:
            s.role = "test" if s.tier == test_tier else "val" if s.tier == val_tier else "train"
    scanners = list(dict.fromkeys(s.profile for s in sessions if s.category == RECON))
    for i, prof in enumerate(scanners):
        group = [s for s in sessions if s.profile == prof]
        if prof == sp["held_out_scanner"]:
            for s in group:
                s.role = "heldout_scanner"
            continue
        tiers = list(dict.fromkeys(s.tier for s in group))
        last = max(s.repeat for s in group)
        test_tier, val_tier = tiers[i % len(tiers)], tiers[(i + 1) % len(tiers)]
        for s in group:
            s.role = "train"
            if s.repeat == last and s.tier == test_tier:
                s.role = "test"
            elif s.repeat == last and s.tier == val_tier:
                s.role = "val"
