"""Dataset-quality report: class distribution, evidence labels, missing values, duplicates.

    python -m src.preprocessing.dataset_report      # writes reports/dataset_quality.{md,json}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from src.detection.train import feature_columns
from src.preprocessing.dataset import CAPTURE, TS, capture_prefix, load_dataset
from src.preprocessing.labeling import (
    AMBIGUOUS, ATTACK, BACKGROUND, EVIDENCE, ORIGINAL_LABEL, STATUS,
    application_port_idle_check, attack_intervals, label_dataset, scenario_for, supported_classes, trainable_mask,
)
from src.preprocessing.lab_data import lab_root, load_lab_set, load_manifest
from src.preprocessing.schema import LABEL, read_flow_csv
from src.utils.config import PROJECT_ROOT, class_names, get_path, load_config

LOCAL_SCHEMA_SAMPLE = PROJECT_ROOT / "tests" / "fixtures" / "local_cicflowmeter_cni0.csv"


def _pct(a: float, b: float) -> str:
    return "–" if not b else f"{100 * a / b:.1f}%"


def duplicate_analysis(df: pd.DataFrame, features: list[str], label_col: str) -> dict[str, Any]:
    h = pd.util.hash_pandas_object(df[features], index=False)
    by_vec = df.assign(_h=h.to_numpy()).groupby("_h")[label_col].nunique()
    return {
        "rows": int(len(df)),
        "duplicate_feature_vectors": int(h.duplicated().sum()),
        "duplicate_fraction": float(h.duplicated().mean()) if len(df) else 0.0,
        "vectors_with_conflicting_labels": int((by_vec > 1).sum()),
        "duplicate_fraction_by_label": {int(k): float(g.duplicated().mean())
                                        for k, g in h.groupby(df[label_col].to_numpy())},
    }


def build_report(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    names = class_names(cfg)
    benign = cfg["benign_label"]
    df = load_dataset(cfg)
    features = feature_columns(df, cfg)
    lab = label_dataset(df, cfg)
    supported, attack_counts = supported_classes(lab, cfg)

    captures = []
    for cap, g in df.groupby(CAPTURE):
        sc = scenario_for(cap, cfg) or {}
        st = lab.loc[g.index, STATUS].value_counts()
        captures.append({
            "capture": cap, "label": int(g[LABEL].iloc[0]), "flows": int(len(g)),
            "start": str(g[TS].min()), "seconds": round(float((g[TS].max() - g[TS].min()).total_seconds()), 1),
            "attack": int(st.get(ATTACK, 0)), "background": int(st.get(BACKGROUND, 0)),
            "ambiguous": int(st.get(AMBIGUOUS, 0)), "observability": sc.get("observability", "benign"),
        })

    per_class = []
    for c in sorted(df[LABEL].unique()):
        m = lab[ORIGINAL_LABEL] == c
        st = lab.loc[m, STATUS].value_counts()
        ev = lab.loc[m, EVIDENCE].value_counts()
        sc = next((scenario_for(cap, cfg) for cap in lab.loc[m, CAPTURE].unique()), None) or {}
        n = int(m.sum())
        per_class.append({
            "label": int(c), "name": names[int(c)], "original_flows": n,
            "attack_flows": int(st.get(ATTACK, 0)), "direct": int(ev.get("direct", 0)),
            "post_compromise": int(ev.get("post_compromise", 0)),
            "background_flows": int(st.get(BACKGROUND, 0)), "ambiguous_flows": int(st.get(AMBIGUOUS, 0)),
            "label_quality": (1.0 if c == benign else (st.get(ATTACK, 0) / n if n else 0.0)),
            "observability": "benign" if c == benign else sc.get("observability"),
            "trainable": c == benign or int(c) in supported,
        })

    num = df[features].apply(pd.to_numeric, errors="coerce")
    vals = num.to_numpy(dtype=float)
    missing = {
        "nan_by_column": {k: int(v) for k, v in num.isna().sum().items() if v},
        "inf_by_column": {k: int(v) for k, v in zip(features, np.isinf(vals).sum(axis=0)) if v},
        "negative_by_column": {k: int(v) for k, v in (num < 0).sum().items() if v},
        "constant_columns": [c for c, v in num.nunique(dropna=False).items() if v <= 1],
        "rows_with_any_nan_or_inf": int((~np.isfinite(vals)).any(axis=1).sum()),
    }
    schema = {}
    if LOCAL_SCHEMA_SAMPLE.is_file():
        local_cols = set(read_flow_csv(LOCAL_SCHEMA_SAMPLE).columns)
        ds_cols = set(c for c in df.columns if not c.startswith("_"))
        schema = {"dataset_columns": len(ds_cols), "local_columns": len(local_cols),
                  "only_in_local_build": sorted(local_cols - ds_cols),
                  "only_in_dataset": sorted(ds_cols - local_cols),
                  "excluded_columns": cfg["features"]["exclude_columns"]}

    keep = trainable_mask(lab, cfg) & (lab[LABEL].isin([benign, *supported]))
    train_view = lab[keep]
    counts_orig = df[LABEL].value_counts()
    counts_new = train_view[LABEL].value_counts()
    imbalance = {
        "original": {"benign": int(counts_orig.get(benign, 0)), "attack": int((df[LABEL] != benign).sum()),
                     "max_min_ratio": float(counts_orig.max() / counts_orig.min())},
        "evidence": {"benign": int(counts_new.get(benign, 0)), "attack": int((train_view[LABEL] != benign).sum()),
                     "max_min_ratio": float(counts_new.max() / counts_new.min()),
                     "class_counts": {int(k): int(v) for k, v in counts_new.sort_index().items()}},
    }

    lab_sets = []
    root = lab_root(cfg)
    for p in sorted(root.glob("*/manifest.json")) if root.is_dir() else []:
        m = load_manifest(p.parent.name, cfg)
        ls = load_lab_set(m["name"], cfg, drop_ambiguous=False)
        vc = ls[LABEL].value_counts(dropna=False)
        lab_sets.append({"name": m["name"], "kind": m["kind"], "files": len(m["files"]), "note": m.get("note", ""),
                         "benign": int(vc.get(benign, 0)),
                         "attack": int(sum(v for k, v in vc.items() if pd.notna(k) and k != benign)),
                         "ambiguous": int(sum(v for k, v in vc.items() if pd.isna(k)))})

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "flows": int(len(df)), "features": len(features),
        "captures": captures, "per_class": per_class,
        "supported_attack_classes": supported, "attack_evidence_counts": attack_counts,
        "min_class_flows": cfg["labeling"]["min_class_flows"],
        "background_action": cfg["labeling"]["background_action"],
        "application_port_idle_check": application_port_idle_check(df, cfg),
        "attack_intervals": attack_intervals(lab, TS),
        "missing": missing, "schema": schema,
        "duplicates_original": duplicate_analysis(df, features, LABEL),
        "duplicates_evidence": duplicate_analysis(train_view, features, LABEL),
        "imbalance": imbalance,
        "lab_sets": lab_sets,
    }


def render_markdown(r: dict[str, Any]) -> str:
    L = ["# Dataset quality report", "",
         f"Generated {r['generated_at'][:19]}Z by `python -m src.preprocessing.dataset_report` from "
         f"`yigitsever/kubernetes-dataset` ({r['flows']:,} flows, 14 per-capture CSVs, {r['features']} candidate features).", "",
         "## Why per-flow labels were needed", "",
         "The published labels are per capture: every flow in an attack capture carries the attack label. Those "
         "captures were taken on the whole node, so they also contain DNS, CoreDNS health checks, OVN southbound-"
         "database traffic (:6642), API-server traffic (:6443) and MetalLB (:7472) that would exist without any "
         "attack. A classifier trained on those labels learns to call ordinary cluster background an attack.", "",
         "The dataset ships no attack timestamps, attacker addresses or packet captures, only flow CSVs, so per-flow "
         "ground truth has to come from evidence inside each capture combined with the scenario definition. The "
         "rules are in `config/settings.yaml` → `labeling`, and the code is in `src/preprocessing/labeling.py`:", "",
         "| Status | Evidence | Rule |", "|---|---|---|",
         "| attack | direct | flow to the scenario's **target application** port (Node-RED :1880, Grafana :3000, InfluxDB :8086). A port only counts for a scenario that targets that application. |",
         "| attack | post_compromise | (RCE/escape scenarios only) connection *opened by* the attacked pod, which never opens a connection as a client in any benign capture: the reverse shell to :9001, API-server access, HTTPS downloads |",
         "| background | infrastructure | (protocol:port) signature that recurs in the pure background capture, with neither endpoint involved in the attack |",
         "| background | benign_tuple | the exact client/server/protocol/service tuple occurs in a benign capture, with no attack endpoint involved |",
         "| ambiguous | none | anything else: kept for analysis, **never used for training or as test ground truth** |", "",
         f"Confirmed background flows from attack captures are treated as **{r['background_action']}** "
         "(`labeling.background_action`; `exclude` drops them instead).", "",
         "### Validation of the `direct` rule", "",
         "The `direct` rule assumes that no benign workload used the applications while attack captures were being "
         "recorded. If that held, application ports that the scenario does *not* target should be silent. Flows on "
         "each non-targeted application port, per attack capture:", "",
         "| Capture | Flows on non-targeted application ports |", "|---|---|"]
    for cap, ports in r["application_port_idle_check"].items():
        L.append(f"| {cap} | " + ", ".join(f":{p} = {n}" for p, n in ports.items()) + " |")
    total = sum(sum(p.values()) for p in r["application_port_idle_check"].values())
    L += ["", f"Total: **{total}** flows. "
          + ("Application ports are idle unless attacked, which supports the rule." if total == 0 else
             "Some non-targeted application ports carry traffic, so the `direct` rule is not fully supported.")
          + " The benign captures show why a port alone is no evidence: there, every :1880 and :3000 flow comes "
          "from the same ingress gateway address as the attacks.", "",
          "## Captures", "",
          "| Capture | Label | Flows | Duration (s) | Attack | Background | Ambiguous | Observability |",
          "|---|---|---|---|---|---|---|---|"]
    for c in r["captures"]:
        L.append(f"| {c['capture']} | {c['label']} | {c['flows']:,} | {c['seconds']} | {c['attack']} | "
                 f"{c['background']} | {c['ambiguous']} | {c['observability']} |")
    L += ["", "## Label quality per class", "",
          "Label quality is the fraction of the originally labelled flows that carry attack evidence.", "",
          "| Class | Original flows | Attack (direct + post-compromise) | Background | Ambiguous | Label quality | Observability | Trained |",
          "|---|---|---|---|---|---|---|---|"]
    for c in r["per_class"]:
        atk = "–" if c["label"] == 0 else f"{c['attack_flows']} ({c['direct']} + {c['post_compromise']})"
        L.append(f"| {c['label']} {c['name']} | {c['original_flows']:,} | {atk} | {c['background_flows']} | "
                 f"{c['ambiguous_flows']} | {c['label_quality']:.1%} | {c['observability']} | "
                 f"{'yes' if c['trainable'] else 'no'} |")
    tot = {k: sum(c[k] for c in r["per_class"] if c["label"] != 0) for k in ("original_flows", "attack_flows", "background_flows", "ambiguous_flows")}
    L += ["", f"Across all attack captures, {tot['original_flows']:,} flows are labelled as attacks. Of these, "
          f"**{tot['attack_flows']:,}** carry attack evidence, **{tot['background_flows']:,}** are confirmed background "
          f"and **{tot['ambiguous_flows']}** are ambiguous.", "",
          f"A class is trained only when it has at least {r['min_class_flows']} attack-evidence flows "
          f"(`labeling.min_class_flows`). Trained attack classes: {r['supported_attack_classes']}.", "",
          "### Observability", "",
          "* **network**: the attack itself sends traffic to the target application, e.g. recon, the InfluxDB "
          "auth bypass, the Grafana CVEs and the Node-RED RCE.",
          "* **kubernetes_api**: CVE-2021-25741 is triggered by a pod spec submitted to the API server and takes "
          "effect inside the kubelet. Neither step appears on the captured pod network: this capture's API-server "
          "flows come from the same infrastructure clients at the same rate as in the benign captures.",
          "* **host_runtime**: CVE-2021-30465, CVE-2022-23648 and CVE-2019-5736 (runc/containerd), and the container "
          "escape in `attack-pods`, happen inside the node. These three CVE captures contain **no flow outside cluster "
          "background**. The escape capture contains only the Node-RED initial-access chain, which is network-identical "
          "to the RCE scenario (class 3).", "",
          "**The network-flow classifier cannot detect classes 7–10, or the escape step of class 4.** The 11-class "
          "mapping is kept for dashboard and API compatibility, but these classes are reported as *not "
          "network-observable* rather than given a meaningless F1. Classes 1 and 5 are network-observable, but the "
          "dataset holds only 2 and 1 attack flows for them, which is too few to train or evaluate.", "",
          "### Derived attack intervals", "",
          "These are the time spans of attack-evidence flows, derived from the flows themselves; the dataset publishes "
          "no attack execution times.", "", "| Capture | First | Last | Seconds | Flows |", "|---|---|---|---|---|"]
    for cap, iv in r["attack_intervals"].items():
        L.append(f"| {cap} | {iv['first']} | {iv['last']} | {iv['seconds']:.1f} | {iv['flows']} |")
    m = r["missing"]
    L += ["", "## Missing and invalid feature values", "",
          f"* Rows with any NaN/inf feature: {m['rows_with_any_nan_or_inf']:,} of {r['flows']:,}",
          f"* NaN by column: {m['nan_by_column'] or 'none'}",
          f"* inf by column: {m['inf_by_column'] or 'none'}",
          f"* Negative values by column (CICFlowMeter uses -1 for 'not observed', e.g. initial window bytes): "
          f"{m['negative_by_column'] or 'none'}",
          f"* Constant columns ({len(m['constant_columns'])}): {', '.join(m['constant_columns']) or 'none'}", ""]
    s = r["schema"]
    if s:
        L += ["### Dataset schema vs the local CICFlowMeter build", "",
              f"The dataset has {s['dataset_columns']} columns and the local build emits {s['local_columns']}. "
              f"Only in the local build: {', '.join(s['only_in_local_build'])}. Only in the dataset: "
              f"{', '.join(s['only_in_dataset'])}. That column was renamed and redefined (`Total Connection Flow Time`), "
              f"so it is excluded (`features.exclude_columns`). Columns only in the local build are ignored at inference "
              "because the model uses the dataset feature set.", ""]
    d0, d1 = r["duplicates_original"], r["duplicates_evidence"]
    L += ["## Duplicates", "",
          "| | Rows | Duplicate feature vectors | Fraction | Vectors with conflicting labels |", "|---|---|---|---|---|",
          f"| Original labels | {d0['rows']:,} | {d0['duplicate_feature_vectors']:,} | {d0['duplicate_fraction']:.1%} | {d0['vectors_with_conflicting_labels']} |",
          f"| Evidence labels (trainable flows) | {d1['rows']:,} | {d1['duplicate_feature_vectors']:,} | {d1['duplicate_fraction']:.1%} | {d1['vectors_with_conflicting_labels']} |",
          "", "Duplicate fraction per evidence label: "
          + ", ".join(f"{k}: {v:.1%}" for k, v in d1["duplicate_fraction_by_label"].items()) + ".", "",
          "Training removes exact duplicate (features, label) rows *after* the split, within the training part only. "
          "Every model records how many test rows have an identical feature vector in training "
          "(`leakage_checks` in `metrics.json`).", "",
          "## Class imbalance", "",
          f"* Original labels: {r['imbalance']['original']['benign']:,} benign vs {r['imbalance']['original']['attack']:,} "
          f"attack flows; largest:smallest class = {r['imbalance']['original']['max_min_ratio']:.0f}:1.",
          f"* Evidence labels: {r['imbalance']['evidence']['benign']:,} benign vs {r['imbalance']['evidence']['attack']:,} "
          f"attack flows; largest:smallest trained class = {r['imbalance']['evidence']['max_min_ratio']:.0f}:1. "
          f"Class counts: {r['imbalance']['evidence']['class_counts']}.", "",
          "The minority classes are tiny: after a 75/25 temporal split, classes 3, 4 and 6 have only a handful of "
          "test flows. Their per-class scores carry very wide uncertainty, so `reports/model_comparison.md` gives "
          "supports and confidence intervals alongside them.", ""]
    if r["lab_sets"]:
        L += ["## Laboratory sets (independent ground truth)", "",
              "These were recorded on this cluster with the controlled traffic generator. Ground truth comes from the "
              "attacker pod address and target port in each manifest. The attacker pod's other flows are ambiguous "
              "and excluded; in the recon runs these are its DNS lookups to CoreDNS (UDP 53), several per HTTP "
              "request because of the cluster search domains.", "",
              "| Set | Kind | Windows | Benign | Attack | Ambiguous | Note |", "|---|---|---|---|---|---|---|"]
        for s in r["lab_sets"]:
            L.append(f"| {s['name']} | {s['kind']} | {s['files']} | {s['benign']} | {s['attack']} | {s['ambiguous']} | {s['note']} |")
        L.append("")
    L += ["## Limitations", "",
          "* The per-flow labels are inferred from evidence, not published ground truth. The rules are conservative: "
          "no address or port alone makes a flow an attack, and anything that is neither attack-linked nor confirmed "
          "background stays ambiguous.",
          "* `post_compromise` evidence counts every new outbound connection of the attacked pod as attacker "
          "activity. That is well supported for the reverse shell (:9001 to a host seen in no benign capture) and "
          "for API-server access (the Node-RED pod never calls it in benign data). It is plausible, but unconfirmed, "
          "for the HTTPS connections.",
          "* Each attack scenario was executed **once**. No class has independent dataset runs, so dataset-based "
          "generalisation to a new execution cannot be measured for any class except via the lab recon runs.",
          "* Background flows confirmed inside attack captures are relabelled as benign. This is correct for "
          "infrastructure traffic but means the benign class now includes flows recorded during attacks.", ""]
    return "\n".join(L)


def main() -> None:
    cfg = load_config()
    r = build_report(cfg)
    out = get_path("reports_dir", cfg)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dataset_quality.json").write_text(json.dumps(r, indent=2, default=str))
    (out / "dataset_quality.md").write_text(render_markdown(r))
    print("wrote", out / "dataset_quality.md")


if __name__ == "__main__":
    main()
