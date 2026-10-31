"""Run the dataset-generation plan, one session at a time.

    python -m src.datagen.run --dry-run                 # print the plan and limits, touch nothing
    python -m src.datagen.run                           # run every session without an ok manifest
    python -m src.datagen.run --only recon-seq_wordlist-high-r1
    python -m src.datagen.run --retry-failed --limit 5

Sessions never overlap: an exclusive lock guards the runner and no session starts
while another datagen Job is still active. Completed sessions (status ok) are skipped,
so an interrupted run can be resumed.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import sys
import time

from src.datagen import kube
from src.datagen.plan import build_plan, load_datagen_config
from src.datagen.session import dirs, run_session
from src.utils.config import load_config


def _status(manifests, sid: str) -> str | None:
    p = manifests / f"{sid}.json"
    return json.loads(p.read_text()).get("status") if p.is_file() else None


def interleave(plan: list) -> list:
    """Execution order mixing categories evenly, so class does not correlate with capture time."""
    groups = [[s for s in plan if s.category == c] for c in dict.fromkeys(s.category for s in plan)]
    keyed = [((i + 0.5) / len(g), gi, s) for gi, g in enumerate(groups) for i, s in enumerate(g)]
    return [s for _, _, s in sorted(keyed, key=lambda t: (t[0], t[1]))]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", nargs="*", help="session IDs")
    ap.add_argument("--retry-failed", action="store_true")
    ap.add_argument("--limit", type=int, help="run at most N sessions")
    args = ap.parse_args(argv)

    dcfg, cfg = load_datagen_config(), load_config()
    plan = interleave(build_plan(dcfg))
    d = dirs(dcfg)
    todo = []
    for s in plan:
        st = _status(d["manifests"], s.session_id)
        if args.only and s.session_id not in args.only:
            continue
        if st == "ok" or (st == "failed" and not args.retry_failed and not args.only):
            continue
        todo.append(s)
    if args.limit:
        todo = todo[:args.limit]
    if args.dry_run:
        for s in plan:
            print(f"{s.index:2d} {s.session_id:38s} {s.role:16s} apps={','.join(s.apps):24s} seed={s.seed} "
                  f"{s.params} [{_status(d['manifests'], s.session_id) or 'pending'}]")
        print(f"\n{len(plan)} sessions, {len(todo)} to run; limits: {dcfg['limits']}")
        return

    lock = open(d["manifests"].parent / "datagen.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("another datagen run holds the lock")
    ns = dcfg["kubernetes"]["namespace"]
    kube.sync_script(dcfg)
    for i, s in enumerate(todo):
        active = kube.active_datagen_jobs(ns)
        if active:
            sys.exit(f"datagen Job(s) still active: {active}; not starting {s.session_id}")
        print(f"[{i + 1}/{len(todo)}] {s.session_id} ({s.role}, apps={s.apps})", flush=True)
        meta = run_session(s, dcfg, cfg)
        flows = (meta.get("conversion") or {}).get("flows")
        print(f"    -> {meta['status']} flows={flows} requests={(meta.get('generator') or {}).get('requests')} "
              f"{meta['error'] or ''}", flush=True)
        if i < len(todo) - 1:
            time.sleep(dcfg["limits"]["gap_seconds"])


if __name__ == "__main__":
    main()
