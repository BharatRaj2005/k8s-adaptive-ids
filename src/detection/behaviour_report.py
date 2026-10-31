"""Render reports/behavioural_detection.md from reports/behavioural_detection.json.

    python -m src.detection.behaviour_report
"""
from __future__ import annotations

import json
from typing import Any

import numpy as np

from src.utils.config import get_path, load_config

NAMES = {"fixed": "Fixed rule", "adaptive": "Adaptive", "ml": "ML (per source)", "hybrid": "Hybrid (adaptive or ML)",
         "policy": "Controller would act"}


def _r(x: dict[str, Any] | None) -> str:
    """'n/d = p% [lo–hi]'."""
    if not x or not x["of"]:
        return "–"
    lo, hi = x["ci95"]
    return f"{x['n']}/{x['of']} = {100 * x['rate']:.1f}% [{100 * lo:.1f}–{100 * hi:.1f}]"


def _delays(res: dict[str, Any]) -> str:
    d = [s["delay_s"] for s in res["scenarios"].values() if s["delay_s"] is not None]
    return f"median {np.median(d):.1f} s (n={len(d)})" if d else "–"


def summary_table(s: dict[str, Any], detectors: list[str]) -> list[str]:
    L = ["| Metric | " + " | ".join(NAMES[d] for d in detectors) + " |", "|---|" + "---|" * len(detectors)]
    rows = [
        ("Detection rate = recall (attack pairs)", lambda r: _r(r["detection_rate"])),
        ("False-positive rate (benign pairs)", lambda r: _r(r["false_positive_rate"])),
        ("Precision", lambda r: _r(r["precision"])),
        ("Detection delay (detected scenarios)", _delays),
        ("Alerts per window (mean / max)", lambda r: f"{r['alerts_per_window_mean']:.2f} / {r['alerts_per_window_max']}"),
        ("CPU per window (median / p95)", lambda r: (f"{r['cpu_ms_per_window']['median']:.1f} / "
                                                     f"{r['cpu_ms_per_window']['p95']:.1f} ms")
         if r.get("cpu_ms_per_window") else "see note"),
        ("Memory (detector state)", lambda r: f"{r['state_bytes'] / 1024:.0f} KiB JSON" if r.get("state_bytes")
         else ("none (stateless)" if "cpu_ms_per_window" in r else "see note")),
    ]
    for name, f in rows:
        L.append(f"| {name} | " + " | ".join(f(s["results"][d]) for d in detectors) + " |")
    return L


def scenario_table(s: dict[str, Any], detectors: list[str]) -> list[str]:
    L = ["| Scenario | Req/s per pod | Requests | " + " | ".join(f"{NAMES[d]}: windows" for d in detectors)
         + " | " + " | ".join(f"{NAMES[d]}: delay" for d in detectors) + " |",
         "|---|---|---|" + "---|" * (2 * len(detectors))]
    first = s["results"][detectors[0]]["scenarios"]
    for n, sc in first.items():
        cells = []
        for d in detectors:
            w = s["results"][d]["scenarios"][n]["windows"]
            cells.append(f"{w['n']}/{w['of']}")
        for d in detectors:
            v = s["results"][d]["scenarios"][n]["delay_s"]
            cells.append("missed" if v is None else f"{v:.0f} s")
        L.append(f"| {n} | {sc.get('rate_per_s') or '–'} | {sc.get('requests') or '–'} | " + " | ".join(cells) + " |")
    return L


def render(r: dict[str, Any]) -> str:
    b, a = r["config"], r["config"]["adaptive"]
    ses = {s["name"]: s for s in r["sessions"]}
    all4 = ["fixed", "adaptive", "ml", "hybrid", "policy"]
    beh = ["fixed", "adaptive"]
    L = ["# Behavioural detection: fixed vs adaptive, flow-level ML and hybrid", "",
         f"Generated {r['generated_at'][:19]} by `python -m src.detection.behavior_eval` and "
         "`python -m src.detection.behaviour_report`. Every number comes from recorded capture windows, replayed in "
         "time order. Nothing is simulated.", "",
         "## What is compared", "",
         f"* **Fixed rule** (`src/detection/behavior.py`, unchanged): one source opens ≥ {b['min_flows']} TCP flows to "
         f"one destination service in a window, at ≥ {b['min_rate_per_s']} flows/s.",
         "* **Adaptive** (`src/detection/adaptive_behavior.py`): the fixed rule plus two learned thresholds per service "
         f"(`median + {a['k']}·max(1.4826·MAD, min_scale)` of earlier non-alerting values, between a floor and the "
         "fixed level):",
         f"  * `adaptive_rate`: per-window rate, with at least {a['min_flows']} flows;",
         f"  * `slow_scan`: flows over the last {a['horizon_s']:.0f} s.",
         "  * The fixed rule's thresholds act until a service has "
         f"{a['warmup']} values. Alerting values are never learned.",
         f"* **ML (per source)**: a source is flagged in a window when the active per-flow model (`{r['model']}`) "
         f"classifies ≥ {r['eval_config']['ml_min_flows']} of its flows as an attack. This is flow-level ML "
         "aggregated per source; the pure flow-level results are in their own table below.",
         "* **Hybrid**: adaptive OR ML, i.e. everything that is shown to the operator. Behavioural and ML alerts stay "
         "separate records (`behavior_alerts` vs `detections`), and the controller correlates them per source.",
         "* **Controller would act**: the MAPE-K decision rules replayed on the same evidence. A fixed-rule burst acts. "
         "So does ML with one flow at ≥ 0.9 confidence, or 3 flows at ≥ 0.6 within 300 s, or a ≥ 0.6 flow "
         "corroborated by a behavioural alert. A learned-threshold alert acts only with a ≥ 0.6 ML flow from the same "
         "source within 300 s. This is the deception trigger, which needs a lower false-positive rate than what is "
         "merely shown.", "",
         "**Unit of evaluation:** a (window, source) pair. It is an attack pair when one of the session's attacker "
         "pods sent TCP flows in that window, and a benign pair for every other source with TCP flows in the window. "
         "The attacker pods are known from the Jobs that ran them. Brackets show 95% Wilson intervals. Delay is "
         "the end of the first alerting window minus the first request in the generator's own log.", "",
         "**Calibration versus evaluation:**",
         "* `session1`, the earlier lab windows, was used while developing the adaptive detector (two bugs were found "
         "and fixed on it). Its recon run 1 is also in the ML model's training data. It is calibration only.",
         "* `session2`, `session3` and `session4` were recorded after all parameters were fixed and were never used "
         "to change anything. They are the held-out evaluation.",
         "* The dataset replays were never used for development either.", ""]

    if "session2" in ses:
        s = ses["session2"]
        L += ["## 1. Held-out lab session: recon at different speeds (session2)", "",
              f"{s['windows']} windows. The session runs 5 minutes of benign-only traffic, then five recon Jobs one "
              "after another, with 1 minute of benign-only traffic between Jobs. The benign generator runs throughout.",
              "", *summary_table(s, all4), "", *scenario_table(s, all4), "",
              f"Adaptive alert types: {s['results']['adaptive'].get('alert_types')}.", ""]
    fl = (ses.get("session2") or {}).get("flow_level_ml")
    if fl:
        L += ["### Flow-level ML on the same windows", "",
              f"Share of each scanner's TCP flows that `{fl['model']}` classifies as an attack. Benign flows "
              f"classified as an attack: {_r(fl['benign'])}.", "",
              "| Scenario | Flows flagged | As Node-RED Reconnaissance | Median confidence |", "|---|---|---|---|"]
        for n, v in fl["scenarios"].items():
            L.append(f"| {n} | {_r(v['flows_flagged'])} | {_r(v['as_recon'])} | {v['confidence_median']:.2f} |")
        L += ["", "**How far this generalises.** These are new executions, from new pods and at new speeds, of the "
              "**same scanner** that produced `recon_run1` in the model's training data: the same path list and the "
              "same target. The result shows that the classifier recognises this scanner at any rate. It does **not** "
              "show that it recognises other scanners; see section 3.", ""]
    if "session3" in ses:
        s = ses["session3"]
        L += ["## 2. Changing benign traffic (session3, no attackers)", "",
              "The session runs 3 minutes at the normal benign rate, then 6 minutes with the generator's request rate "
              "raised about 3× (delay 0.3–1.3 s instead of 1–4 s; the change restarts the pod, which then appears "
              "under a new IP), then the normal rate again. Every alert in this session is a false positive.", "",
              *summary_table(s, all4), ""]
    L += ["## 3. Previously unseen scanners", ""]
    if "session4" in ses:
        s = ses["session4"]
        L += ["### 3a. Second lab scanner (session4)", "",
              "A differently built scan that the model never saw: other paths (documented Grafana API and UI "
              "endpoints), another target application (Grafana :3000; the model's recon training data is Node-RED "
              "only), and its own HEAD/GET mix.", "",
              *summary_table(s, all4), "", *scenario_table(s, all4), ""]
        f4 = s.get("flow_level_ml")
        if f4:
            L += ["| Scenario | Flows flagged by ML | As Node-RED Reconnaissance | Median confidence |", "|---|---|---|---|"]
            for n, v in f4["scenarios"].items():
                L.append(f"| {n} | {_r(v['flows_flagged'])} | {_r(v['as_recon'])} | "
                         f"{(v['confidence_median'] or 0):.2f} |")
            L.append("")
    if "dataset_recon_tool" in ses:
        s = ses["dataset_recon_tool"]
        L += ["### 3b. The dataset's own recon tool (other scanner, other cluster)", "",
              f"The dataset's reconnaissance capture, cut into 10 s windows by flow start time ({s['windows']} "
              f"windows). It is preceded by {s['warmup_windows']} windows of the dataset's benign Node-RED capture, "
              "which only warm up the adaptive state and are not scored. ML is not scored here because the model was "
              "trained on part of this capture. The model-comparison leave-one-run-out result is the ML evidence: a "
              "model trained without this capture detects **0%** of its recon flows "
              "(`reports/model_comparison.md`).", "", *summary_table(s, beh), ""]
    if "dataset_nodered_benign" in ses:
        s = ses["dataset_nodered_benign"]
        L += ["## 4. Benign traffic aggregated behind one address (dataset Node-RED capture)", "",
              "In the dataset cluster, every external client reaches the applications through the ingress gateway "
              "`100.64.0.2`. The benign Node-RED capture therefore shows one source sending about 4–5 flows/s to "
              "Node-RED, i.e. the combined load of all its users.", "", *summary_table(s, beh), "",
              "**Both behavioural detectors produce false alerts here, and the adaptive one more**, because by design "
              "it can only be more sensitive than the fixed rule. Per-source volume rules cannot tell many users "
              "behind one NAT or gateway address from one scanner. Where such an address exists, it must be listed in "
              "`behavior.ignore_sources` (and is then covered only by the ML classifier), or it needs a separate "
              "per-source baseline that is allowed above the fixed level. In this lab, clients are individual pods, "
              "so this does not occur (sessions 2 and 3).", ""]
    if "session1" in ses:
        s = ses["session1"]
        L += ["## 5. Calibration session (session1, not an evaluation)", "",
              *summary_table(s, all4), ""]
    L += ["## Policy change made after session3 (not independently validated)", "",
          "Session 3 showed that a benign client which speeds up raises repeated learned-threshold alerts. Under the "
          "earlier rule (act after 2 alert windows), the controller would have deployed decoys for it. Two changes "
          "were made after seeing this, so **session 3 is not independent evidence for them**:", "",
          "* `deception.thresholds.behavior_medium_requires_ml: true`: learned-threshold alerts stay *suspicious "
          "behaviour* (shown, recorded) and act only with ML corroboration.",
          "* ML corroboration counts only detections at ≥ `medium_confidence` (0.6), the controller's existing floor "
          "for ML evidence. The benign pod's ML false positives in session 3 had confidence 0.30–0.34; the scanners "
          "in sessions 2 and 4 have many flows at ≥ 0.6.", "",
          "The detector thresholds themselves were not changed. A fresh recording would be needed to confirm the "
          "policy on unseen data.", "",
          "## Overhead", "",
          "* **CPU:** time to analyse one window, measured during the replay. ML inference is not included: it runs "
          "anyway for classification, and its cost is in `reports/performance.md`.",
          "* **Memory:** the adaptive detector keeps a bounded JSON state (per-service histories capped at "
          f"{a['history_size']} values, plus the flows of the last {a['horizon_s']:.0f} s) in the SQLite `kv` table. "
          "The fixed rule is stateless.", "",
          "## Conclusions", ""]
    s2 = ses.get("session2")
    if s2:
        res = s2["results"]
        L += [f"* **Slow recon.** On the held-out session the fixed rule detected {_r(res['fixed']['detection_rate'])} "
              f"of attack pairs and the adaptive detector {_r(res['adaptive']['detection_rate'])}, both with "
              f"{res['adaptive']['false_positive_rate']['n']} false positives. The adaptive detector catches medium-rate "
              "recon in every window, and low-rate and distributed recon only after its 120 s horizon has accumulated. "
              "It misses the very-low-rate scan (1 request per 6 s), which is close to the benign clients' own rate.",
              f"* **ML on the known scanner.** Per-source ML detected {_r(res['ml']['detection_rate'])} of attack pairs, "
              "including the slow ones, because it recognises the scanner's flows themselves rather than their volume.",
              "* **Hybrid.** Hybrid equals ML on the known scanner. Behavioural detection matters where ML does not "
              "know the scanner (section 3) and where the per-flow model cannot be trusted (unfamiliar applications, "
              "`reports/unknown_traffic.md`).", ""]
    s4, s3 = ses.get("session4"), ses.get("session3")
    if s4:
        r4 = s4["results"]
        L += [f"* **Unseen scanner.** On the second lab scanner, the fixed rule detected {_r(r4['fixed']['detection_rate'])}, "
              f"adaptive {_r(r4['adaptive']['detection_rate'])}, ML {_r(r4['ml']['detection_rate'])} and hybrid "
              f"{_r(r4['hybrid']['detection_rate'])}. At flow level the classifier flagged only part of this scanner's "
              "flows, at lower confidence, and labelled them *Node-RED Reconnaissance*, the only recon class it knows. "
              "The two detectors cover different windows, which is why hybrid is higher than either."]
    if s3:
        r3 = s3["results"]
        L += [f"* **Changing benign traffic.** With the benign rate raised about 3×, the adaptive detector raised "
              f"{_r(r3['adaptive']['false_positive_rate'])} false alerts and the fixed rule "
              f"{_r(r3['fixed']['false_positive_rate'])}. Under the current policy the controller would act on "
              f"{_r(r3['policy']['false_positive_rate'])} of these benign pairs (see the policy change above)."]
    L.append("")
    L += ["## Limitations", "",
          "* Only flow metadata is used. HTTP paths and status codes are not visible in CICFlowMeter records.",
          "* Recon slower than normal clients' request rates cannot be separated by volume.",
          "* Many users behind one NAT or gateway address look like one scanner (section 4).",
          "* The adaptive detector assumes its warm-up traffic is benign. Its fixed-level cap limits how far a "
          "learned threshold can move.",
          "* All attackers are the lab's own generators (HTTP requests only). No other scanner software was run.", ""]
    return "\n".join(L)


def main() -> None:
    cfg = load_config()
    path = get_path("reports_dir", cfg) / "behavioural_detection.json"
    path.with_suffix(".md").write_text(render(json.loads(path.read_text())))
    print("wrote", path.with_suffix(".md"))


if __name__ == "__main__":
    main()
