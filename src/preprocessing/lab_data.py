"""Labelled flow sets recorded in the isolated lab.

A lab set is a snapshot of captured flow CSVs plus a manifest describing its
ground truth, which is known because the lab traffic is generated under control:

* benign set  - every flow is benign (only the benign generator and cluster
                background were running)
* attack set  - flows between the attacker pod and the attacked port carry the
                attack label, other attacker-pod flows are dropped as ambiguous,
                and all remaining flows are benign

    python -m src.preprocessing.lab_data snapshot --name benign_run1 --from 2026-10-30T17:34:00Z --to 2026-10-30T17:40:00Z
    python -m src.preprocessing.lab_data snapshot --name recon_run1 --from ... --to ... \
        --attacker-ip 10.42.0.181 --target-port 1880 --attack-label 2
    python -m src.preprocessing.lab_data list
"""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.preprocessing.dataset import CAPTURE, CAPTURE_FILE, TS
from src.preprocessing.schema import DST_IP, DST_PORT, LABEL, SRC_IP, SRC_PORT, TIMESTAMP, parse_timestamps, read_flow_csv
from src.utils import db
from src.utils.config import get_path, load_config

MANIFEST = "manifest.json"


def lab_root(cfg: dict[str, Any] | None = None) -> Path:
    return get_path("processed_dir", cfg).parent / "lab"


def _parse_time(s: str) -> datetime:
    t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def snapshot(name: str, start: str, end: str, attacker_ips: list[str] | None = None,
             target_port: int | None = None, attack_label: int | None = None, note: str = "",
             cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Copy the flow CSVs of classified capture windows lying entirely within [start, end]."""
    cfg = cfg or load_config()
    if bool(attacker_ips) != (attack_label is not None):
        raise ValueError("attack sets need both --attacker-ip and --attack-label")
    t0, t1 = _parse_time(start), _parse_time(end)
    with db.connect(db.db_path(cfg)) as conn:
        rows = db.query_df(conn, "SELECT pcap_file, started_at, ended_at, csv_file FROM captures "
                                 "WHERE status = 'classified' AND csv_file IS NOT NULL")
    rows = rows[(pd.to_datetime(rows.started_at, utc=True) >= t0) & (pd.to_datetime(rows.ended_at, utc=True) <= t1)]
    if rows.empty:
        raise ValueError("no classified capture windows in that time range")
    out = lab_root(cfg) / name
    if out.exists():
        raise FileExistsError(f"lab set {name} already exists")
    out.mkdir(parents=True)
    flows_dir = get_path("flows_dir", cfg)
    for csv in rows.csv_file:
        shutil.copy2(flows_dir / csv, out / csv)
    manifest = {
        "name": name, "created_at": datetime.now(timezone.utc).isoformat(), "from": start, "to": end,
        "kind": "attack" if attacker_ips else "benign", "attacker_ips": attacker_ips or [],
        "target_port": target_port, "attack_label": attack_label, "note": note,
        "files": sorted(rows.csv_file.tolist()),
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2))
    return manifest


def load_manifest(name: str, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    path = lab_root(cfg) / name / MANIFEST
    if not path.is_file():
        raise FileNotFoundError(f"lab set {name} not found ({path})")
    return json.loads(path.read_text())


def label_flows(df: pd.DataFrame, manifest: dict[str, Any], benign_label: int) -> pd.Series:
    """Ground-truth label per flow; NA marks ambiguous flows."""
    labels = pd.Series(benign_label, index=df.index, dtype="Int64")
    if manifest["kind"] == "attack":
        ips = set(manifest["attacker_ips"])
        involves = df[SRC_IP].isin(ips) | df[DST_IP].isin(ips)
        port = manifest.get("target_port")
        on_port = (df[DST_PORT] == port) | (df[SRC_PORT] == port) if port else pd.Series(True, index=df.index)
        labels[involves] = pd.NA
        labels[involves & on_port] = manifest["attack_label"]
    return labels


def load_lab_set(name: str, cfg: dict[str, Any] | None = None, drop_ambiguous: bool = True) -> pd.DataFrame:
    """Flows of a lab set in the same layout as load_dataset() output."""
    cfg = cfg or load_config()
    manifest = load_manifest(name, cfg)
    frames = []
    for f in manifest["files"]:
        d = read_flow_csv(lab_root(cfg) / name / f)
        d[CAPTURE] = f"lab:{name}:{f.removesuffix('.pcap_Flow.csv')}"
        d[CAPTURE_FILE] = f
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    df[LABEL] = label_flows(df, manifest, cfg["benign_label"])
    df[TS] = parse_timestamps(df[TIMESTAMP])
    if drop_ambiguous:
        df = df[df[LABEL].notna()].copy()
    df[LABEL] = df[LABEL].astype(int) if drop_ambiguous else df[LABEL]
    return df.reset_index(drop=True)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--name", required=True)
    s.add_argument("--from", dest="start", required=True)
    s.add_argument("--to", dest="end", required=True)
    s.add_argument("--attacker-ip", action="append")
    s.add_argument("--target-port", type=int)
    s.add_argument("--attack-label", type=int)
    s.add_argument("--note", default="")
    sub.add_parser("list")
    args = ap.parse_args(argv)
    if args.cmd == "snapshot":
        m = snapshot(args.name, args.start, args.end, args.attacker_ip, args.target_port, args.attack_label, args.note)
        print(json.dumps({k: v for k, v in m.items() if k != "files"}, indent=2), f"\nfiles: {len(m['files'])}")
        df = load_lab_set(args.name, drop_ambiguous=False)
        print("flows by label (<NA> = ambiguous):", df[LABEL].value_counts(dropna=False).to_dict())
    else:
        for p in sorted(lab_root().glob(f"*/{MANIFEST}")):
            m = json.loads(p.read_text())
            print(f"{m['name']:20s} {m['kind']:7s} files={len(m['files']):3d} {m['from']} .. {m['to']} {m['note']}")


if __name__ == "__main__":
    main()
