"""Build the versioned generated dataset from the recorded sessions.

    python -m src.datagen.build            # -> data/generated/{labelled,manifest.json,reports}
                                           #    and reports/balanced_dataset_analysis.md

Steps:
  1. label every session with status ok (src/datagen/labeling.py); failed sessions are listed, not used;
  2. drop discarded rows (invalid, exact duplicates); keep ambiguous rows only for reporting;
  3. split by whole session (roles from src/datagen/plan.py);
  4. training pool = trainable rows of training sessions, feature-vector duplicates removed;
  5. balanced training set: per class up to `balance.target_per_class`, sampled without replacement
     and spread evenly over sessions; a class below target keeps all its rows (shortfall recorded);
  6. natural evaluation sets (validation, test, held-out scanner) are written untouched.
"""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.datagen.labeling import (AMBIGUOUS, APP, BACKGROUND, CATEGORY, DISCARDED, EDGE, GROUND_TRUTH, PROFILE,
                                  REASON, ROLE, SESSION, SESSION_TRAFFIC, STATUS, TIER, label_session_files)
from src.datagen.plan import BENIGN, RECON, build_plan, load_datagen_config, output_dir
from src.datagen.session import model_features
from src.preprocessing.schema import LABEL
from src.utils.config import class_names, load_config, project_path
from src.utils.logging_setup import get_logger

log = get_logger(__name__)
SETS = {"train_natural": "train", "val_natural": "val", "test_natural": "test",
        "heldout_scanner_natural": "heldout_scanner"}


def load_manifests(root: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted((root / "manifests").glob("*.json"))]


def fill_quota(sizes: dict[str, int], target: int) -> dict[str, int]:
    """Per-session counts summing to min(target, total), as even across sessions as possible."""
    total = sum(sizes.values())
    if total <= target:
        return dict(sizes)
    quota, left = {}, target
    remaining = dict(sorted(sizes.items(), key=lambda kv: kv[1]))
    while remaining:
        share = left // len(remaining)
        small = {k: v for k, v in remaining.items() if v <= share}
        if not small:
            extra = left - share * len(remaining)
            for i, k in enumerate(sorted(remaining)):
                quota[k] = share + (1 if i < extra else 0)
            break
        for k, v in small.items():
            quota[k] = v
            left -= v
            del remaining[k]
    return quota


def sample_by_session(df: pd.DataFrame, target: int, rng: np.random.Generator) -> pd.DataFrame:
    if df.empty or target <= 0:
        return df.iloc[0:0]
    quota = fill_quota(df.groupby(SESSION).size().to_dict(), target)
    parts = [g.iloc[rng.choice(len(g), size=quota[s], replace=False)] for s, g in df.groupby(SESSION) if quota[s]]
    return pd.concat(parts).sort_index()


def balance(pool: pd.DataFrame, bcfg: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Undersample by session; never duplicate. Benign = session traffic first, background up to a share."""
    rng = np.random.default_rng(bcfg["random_state"])
    target = int(bcfg["target_per_class"])
    parts, report = [], {}
    for label, g in pool.groupby(LABEL):
        label = int(label)
        if label == 0:
            sess = g[g[STATUS] == SESSION_TRAFFIC]
            bg = g[g[STATUS].isin(BACKGROUND)]
            bg_cap = int(math.floor(bcfg["max_background_share"] * target))
            take_sess = sample_by_session(sess, target - min(bg_cap, len(bg)), rng)
            take_bg = sample_by_session(bg, min(bg_cap, target - len(take_sess)), rng)
            chosen = pd.concat([take_sess, take_bg])
            detail = {"session_traffic": int(len(take_sess)), "background": int(len(take_bg))}
        else:
            chosen = sample_by_session(g, target, rng)
            detail = {}
        parts.append(chosen)
        report[label] = {"available": int(len(g)), "selected": int(len(chosen)), "target": target,
                         "shortfall": max(0, target - int(len(chosen))),
                         "sessions": int(chosen[SESSION].nunique()), **detail}
    return pd.concat(parts).sort_index(), report


def feature_hash(df: pd.DataFrame, feats: list[str]) -> pd.Series:
    return pd.util.hash_pandas_object(df[feats].apply(pd.to_numeric, errors="coerce"), index=False)


def counts(series: pd.Series) -> dict[str, int]:
    return {str(k): int(v) for k, v in series.value_counts(dropna=False).sort_index().items()}


def build(dcfg: dict[str, Any] | None = None, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    dcfg, cfg = dcfg or load_datagen_config(), cfg or load_config()
    root = output_dir(dcfg)
    feats = model_features(cfg)
    roles = {s.session_id: s.role for s in build_plan(dcfg)}
    manifests = load_manifests(root)
    ok = [m for m in manifests if m.get("status") == "ok"]
    failed = [{"session_id": m["session_id"], "error": m.get("error")} for m in manifests if m.get("status") != "ok"]

    frames, sessions = [], []
    for m in ok:
        m["role"] = roles.get(m["session_id"], m.get("role", ""))
        df = label_session_files(root, m, dcfg["labelling"], feats)
        out = root / "labelled" / f"{m['session_id']}.csv"
        df.to_csv(out, index=False)
        frames.append(df)
        st = df[STATUS]
        gen = m.get("generator") or {}
        sess_rows = df[st == SESSION_TRAFFIC]
        sessions.append({
            "session_id": m["session_id"], "role": m["role"], "category": m["category"], "profile": m["profile"],
            "tier": m["tier"], "seed": m["seed"], "applications": m["apps"], "label": int(m["label"]),
            "attack_or_benign": "attack" if m["category"] == RECON else "benign",
            "source_pod": m["pod"]["name"], "source_ip": m["pod"]["ip"],
            "destination_ips": sorted({ip for a in m["apps"] for ip in m["targets"][a]["pod_ips"]}),
            "destination_ports": sorted({m["targets"][a]["port"] for a in m["apps"]}),
            "start": gen.get("first_ts"), "end": gen.get("last_ts"),
            "requests": gen.get("requests"), "connections_logged": len(json.loads((root / m["connections_file"]).read_text())),
            "connections_with_flow": int(sess_rows["_conn_id"].nunique()),
            "packets": (m.get("capture") or {}).get("packets"), "dropped_packets": (m.get("capture") or {}).get("dropped"),
            "flows": int(len(df)), "session_flows": int(len(sess_rows)),
            "status_counts": counts(st),
            "capture_file": f"pcaps/{m['capture']['pcap']}", "feature_csv": m["flows_csv"],
            "labelled_csv": f"labelled/{out.name}", "generator_log": f"raw/{m['session_id']}.log.jsonl",
            "ground_truth_source": GROUND_TRUTH[SESSION_TRAFFIC],
        })
    if not frames:
        raise SystemExit("no completed sessions to build from")
    all_df = pd.concat(frames, ignore_index=True)
    kept = all_df[~all_df[STATUS].isin(DISCARDED)]
    trainable = kept[kept[LABEL].notna()].copy()
    trainable[LABEL] = trainable[LABEL].astype(int)

    # whole sessions per split; feature-duplicates removed inside the training pool only
    split = {name: trainable[trainable[ROLE] == role] for name, role in SETS.items()}
    train = split["train_natural"]
    before = len(train)
    train = train.drop_duplicates(subset=feats + [LABEL])
    split["train_natural"] = train
    conflicting = int(train.groupby(feats, dropna=False)[LABEL].nunique().gt(1).sum())
    balanced, bal_report = balance(train, dcfg["balance"])
    train_hashes = set(feature_hash(train, feats))
    leakage = {name: int(feature_hash(d, feats).isin(train_hashes).sum()) for name, d in split.items()
               if name != "train_natural" and len(d)}
    overlap = {a: sorted(set(split[a][SESSION]) & set(split[b][SESSION]))
               for a in SETS for b in SETS if a < b and len(split[a]) and len(split[b])}
    if any(overlap.values()):
        raise RuntimeError(f"sessions in more than one split: {overlap}")

    lab_dir = root / "labelled"
    for name, d in {**split, "train_balanced": balanced}.items():
        d.to_csv(lab_dir / f"{name}.csv.gz", index=False, compression="gzip")

    names = class_names(cfg)
    held_app = dcfg["split"]["held_out_app"]
    report = {
        "dataset_version": dcfg["dataset_version"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sessions_ok": len(ok), "sessions_failed": failed, "planned_sessions": len(roles),
        "rows_total": int(len(all_df)),
        "status_counts": counts(all_df[STATUS]),
        "ambiguous_reasons": counts(all_df[all_df[STATUS].isin(AMBIGUOUS)][REASON]),
        "discarded": counts(all_df[all_df[STATUS].isin(DISCARDED)][STATUS]),
        "edge_flows": int(all_df[EDGE].sum()),
        "valid_flows": int(len(trainable)),
        "class_counts": {names[int(k)]: int(v) for k, v in trainable[LABEL].value_counts().sort_index().items()},
        "class_counts_session_traffic": {names[int(k)]: int(v) for k, v in
                                         trainable[trainable[STATUS] == SESSION_TRAFFIC][LABEL].value_counts().sort_index().items()},
        "background_counts": counts(trainable[trainable[STATUS].isin(BACKGROUND)][STATUS]),
        "per_application": {f"{a or 'other'}|{names[int(lbl)]}": int(v) for (a, lbl), v in
                            trainable.groupby([APP, LABEL]).size().items()},
        "per_profile": {f"{c}|{p}|{t}": int(v) for (c, p, t), v in
                        trainable[trainable[STATUS] == SESSION_TRAFFIC].groupby([CATEGORY, PROFILE, TIER]).size().items()},
        "split": {name: {"sessions": int(d[SESSION].nunique()), "rows": int(len(d)),
                         "classes": {names[int(k)]: int(v) for k, v in d[LABEL].value_counts().sort_index().items()},
                         "session_traffic": int((d[STATUS] == SESSION_TRAFFIC).sum())}
                  for name, d in {**split, "train_balanced": balanced}.items()},
        "train_dedup": {"before": int(before), "after": int(len(train)), "conflicting_label_vectors": conflicting},
        "balance": {names[k]: v for k, v in bal_report.items()},
        "duplicates_across_splits": leakage,
        "held_out_app": {"app": held_app,
                         "sessions_touching": sorted(s["session_id"] for s in sessions if held_app in s["applications"]),
                         "train_sessions_not_touching": sorted(s["session_id"] for s in sessions
                                                               if s["role"] == "train" and held_app not in s["applications"])},
        "features": feats,
    }
    (root / "reports" / "dataset_quality.json").write_text(json.dumps(report, indent=2, default=str))
    manifest = {
        "dataset_version": dcfg["dataset_version"], "generation_date": report["generated_at"],
        "generator": "kubernetes/traffic-generator/datagen_generator.py", "config": "config/datagen.yaml",
        "capture_interface": cfg["capture"]["interface"], "flow_extractor": "CICFlowMeter (GintsEngelen fork, local build)",
        "label_ids": {"0": names[0], "2": names[2]}, "ground_truth_sources": GROUND_TRUTH,
        "files": {name: f"labelled/{name}.csv.gz" for name in [*SETS, "train_balanced"]},
        "sessions": sessions, "failed_sessions": failed,
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    write_markdown(report, sessions, dcfg)
    return report


def _table(rows: list[list[Any]], head: list[str]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(f"{c:,}" if isinstance(c, int) else str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def write_markdown(rep: dict[str, Any], sessions: list[dict[str, Any]], dcfg: dict[str, Any]) -> None:
    pct = lambda a, b: f"{100 * a / b:.1f}%" if b else "—"
    total = rep["rows_total"]
    st = rep["status_counts"]
    L = [f"# Generated dataset: quality report ({rep['dataset_version']})", "",
         f"Generated {rep['generated_at'][:19]}Z by `python -m src.datagen.build` from "
         f"{rep['sessions_ok']} of {rep['planned_sessions']} planned capture sessions "
         f"(`data/generated/manifest.json`). Every figure below is counted from the labelled flows.", "",
         "## Summary", "",
         _table([["Captured flows (all sessions)", total],
                 ["Valid labelled flows (trainable)", rep["valid_flows"]],
                 ["Ambiguous (excluded from training)", sum(st.get(k, 0) for k in AMBIGUOUS)],
                 ["Discarded (invalid + exact duplicates)", sum(st.get(k, 0) for k in DISCARDED)],
                 ["Flows touching the capture edge (kept, flagged)", rep["edge_flows"]],
                 ["Failed sessions", len(rep["sessions_failed"])]], ["", "Flows"]), "",
         "## Samples per class", "",
         _table([[c, n, rep["class_counts_session_traffic"].get(c, 0), n - rep["class_counts_session_traffic"].get(c, 0)]
                 for c, n in rep["class_counts"].items()],
                ["Class", "Valid flows", "Generator session traffic", "Background (benign)"]), "",
         "Only Benign and Node-RED Reconnaissance (class 2; the dataset's name for path enumeration, here against all "
         "three applications) are generated. No other attack class was produced, by design: see the plan "
         "(`docs/dataset_generation_plan.md`).", "",
         "## Status of every captured flow", "",
         _table([[k, v, pct(v, total)] for k, v in sorted(st.items(), key=lambda kv: -kv[1])], ["Status", "Flows", "Share"]), "",
         "Ambiguous reasons: " + ", ".join(f"{k} ({v:,})" for k, v in rep["ambiguous_reasons"].items()), "",
         "## Samples per application", "",
         _table([[k.split("|")[0], k.split("|")[1], v] for k, v in sorted(rep["per_application"].items())],
                ["Application (by service endpoint)", "Class", "Valid flows"]), "",
         "`other` = flows not involving an application port (cluster background: DNS, kubelet, API server, ...).", "",
         "## Samples per benign profile / scanner (generator session traffic)", "",
         _table([[*k.split("|"), v] for k, v in sorted(rep["per_profile"].items())],
                ["Category", "Profile / scanner", "Tier", "Flows"]), "",
         "## Samples per capture session", "",
         _table([[s["session_id"], s["role"], ",".join(s["applications"]), s["requests"], s["connections_logged"],
                  s["connections_with_flow"], s["session_flows"], s["flows"], s["packets"]]
                 for s in sorted(sessions, key=lambda s: s["session_id"])],
                ["Session", "Role", "Apps", "Requests", "Conns logged", "Conns with flow", "Labelled session flows",
                 "All flows", "Packets"]), "",
         "*Conns with flow* below *Conns logged* means some logged connections produced no matching flow "
         "(see the per-session status counts in the manifest).", ""]
    if rep["sessions_failed"]:
        L += ["### Failed sessions", "", _table([[f["session_id"], f["error"]] for f in rep["sessions_failed"]],
                                                 ["Session", "Error"]), ""]
    d = rep["train_dedup"]
    L += ["## Duplicates", "",
          f"* Exact duplicate rows removed: {st.get('duplicate', 0):,}; invalid rows removed: {st.get('invalid', 0):,}.",
          f"* Feature-vector duplicates removed inside the training pool: {d['before'] - d['after']:,} of {d['before']:,} "
          f"({pct(d['before'] - d['after'], d['before'])}); vectors with conflicting labels: {d['conflicting_label_vectors']:,}.",
          "* Evaluation rows whose feature vector also occurs in training (kept; natural distribution): " +
          ", ".join(f"{k} {v:,}" for k, v in rep["duplicates_across_splits"].items()) + ".", "",
          "## Train / validation / test split (whole sessions)", "",
          _table([[k, v["sessions"], v["rows"], v["session_traffic"],
                   ", ".join(f"{c} {n:,}" for c, n in v["classes"].items())] for k, v in rep["split"].items()],
                 ["Set", "Sessions", "Rows", "Generator session flows", "Classes"]), "",
          f"* Held-out scanner: `{dcfg['split']['held_out_scanner']}`, all of its sessions; never used for training, "
          "validation or tuning.",
          f"* Held-out application: `{rep['held_out_app']['app']}`. {len(rep['held_out_app']['sessions_touching'])} sessions "
          f"touch it; the application fold trains only on the {len(rep['held_out_app']['train_sessions_not_touching'])} "
          "training sessions that never do.",
          "* No session appears in more than one set (checked by the build).", "",
          "## Balance", "",
          _table([[c, v["available"], v["selected"], v["target"], v["shortfall"], v["sessions"],
                   v.get("session_traffic", "—"), v.get("background", "—")] for c, v in rep["balance"].items()],
                 ["Class", "Available (train)", "Selected", "Target", "Shortfall", "Sessions", "Benign session traffic",
                  "Benign background"]), "",
          "Selection is without replacement, spread as evenly as possible across sessions; nothing is duplicated or "
          "synthesised. Validation, test and held-out-scanner sets keep their natural class ratio.", ""]
    path = project_path("reports/balanced_dataset_analysis.md")
    path.write_text("\n".join(L) + "\n")
    (output_dir(dcfg) / "reports" / "dataset_quality.md").write_text("\n".join(L) + "\n")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args(argv)
    rep = build()
    print(json.dumps({k: rep[k] for k in ("sessions_ok", "valid_flows", "class_counts", "status_counts")}, indent=1))


if __name__ == "__main__":
    main()
