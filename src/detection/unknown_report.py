"""Render reports/unknown_traffic.md from reports/unknown_traffic.json.

    python -m src.detection.unknown_report
"""
from __future__ import annotations

import json
from typing import Any

from src.utils.config import get_path, load_config


def _c(x: dict[str, Any]) -> str:
    if not x["of"]:
        return "–"
    lo, hi = x["ci95"]
    return f"{x['n']}/{x['of']} = {100 * x['rate']:.1f}% [{100 * lo:.1f}–{100 * hi:.1f}]"


def _prec(v: float | None) -> str:
    return "–" if v is None else f"{v:.3f}"


def render(r: dict[str, Any], active: dict[str, Any]) -> str:
    u = r["unknown_config"]
    L = ["# Unknown traffic and unseen applications", "",
         f"Generated from `reports/unknown_traffic.json` (`python -m src.detection.loao_eval`, run "
         f"{r['generated_at'][:19]}Z). Brackets show 95% Wilson intervals.", "",
         "## Problem", "",
         "In the model comparison, a model that never saw benign traffic of an application flags most of that "
         "application's traffic as an attack. The per-flow classifier only knows the application through its "
         "attacks, so any flow to it looks like an attack. Here this is measured per application and three "
         "countermeasures are compared.", "",
         "## Mechanisms (`src/detection/unknown.py`)", "",
         "A flow is reported as **Unknown / Requires Investigation**, never as an attack, when an enabled check fires:", "",
         f"* `unfamiliar_service`: the classifier says *attack*, but the destination service had fewer than "
         f"{u['min_benign_service_flows']} benign training flows (an application-aware baseline). It is built from the "
         "training data's benign flows per protocol:port and stored as `service_profile.json` in the model directory.",
         f"* `low_confidence`: the winning class probability is below {u['min_confidence']}.",
         f"* `out_of_distribution`: the mean distance to the 5 nearest training flows (log-scaled, standardised "
         f"features) exceeds the {u['novelty_quantile']} quantile of that distance on validation flows.", "",
         "An unknown flow keeps the model's label for reference. It is stored with `status = unknown` and "
         "`is_malicious = 0`, so the deception controller never deploys a decoy for it.", "",
         "## Leave-one-application-out protocol", "",
         "For each application, all benign flows of its service port are removed from training: dataset captures and "
         "lab sets alike. Attack flows stay in training as known attack patterns. Each fold trains the selected recipe "
         "(ExtraTrees, no class weighting). The decision threshold and the novelty quantile are calibrated on a "
         "validation split of that fold's training pool, which never contains the held-out application. Each fold is "
         "scored on:", "",
         "* **held-out application:** every removed benign flow, plus that application's benign flows in the test "
         "split and the lab evaluation sets;",
         "* **known applications:** the remaining benign test and lab flows (the cost of a mechanism);",
         "* **attacks:** the test split's attack flows plus the held-out lab recon run.", "",
         "Precision counts attack verdicts on all benign flows, held-out and known, as false positives.", ""]
    for f in r["folds"]:
        L += [f"## Fold: {f['application']}", "",
              f"Decision threshold {f['threshold']}, novelty threshold {f['novelty_threshold']:.2f}, "
              f"{f['held_out_training_flows_removed']:,} benign training flows removed, "
              f"{f['services_with_benign_profile']} services with a benign profile. Batch inference including the "
              f"novelty score: {f['inference_us_per_flow']:.0f} µs/flow.", "",
              "| Variant | Held-out app: false positive | Held-out app: unknown | Known apps: false positive | "
              "Known apps: unknown | Attacks detected | Attacks unknown | Attacks missed | Attacks on held-out app "
              "(detected / unknown) | Attack precision |", "|---|---|---|---|---|---|---|---|---|---|"]
        for v, x in f["variants"].items():
            h, k, a = x["held_out_app_benign"], x["known_app_benign"], x["attacks"]
            o = a["on_held_out_app"]
            on = f"{o['detected']['n']} / {o['unknown']['n']} of {o['flows']}" if o["flows"] else "–"
            L.append(f"| {v} | {_c(h['false_positive'])} | {_c(h['unknown'])} | {_c(k['false_positive'])} | "
                     f"{_c(k['unknown'])} | {_c(a['detected'])} | {_c(a['unknown'])} | {_c(a['missed'])} | {on} | "
                     f"{_prec(x['attack_precision'])} |")
        L.append("")
    L += ["## Findings", "",
          "* Without any check, the held-out application's benign traffic is flagged at a rate that depends on how "
          "much its traffic resembles known attacks on the same port. Node-RED is worst because the only known "
          ":1880 traffic is reconnaissance.",
          "* `unfamiliar_service` removes these false positives in every fold and leaves known applications unchanged. "
          "The fold without a held-out application shows its cost on fully known traffic. The price: attacks against "
          "an application without a benign profile are reported as **unknown** instead of as an attack. They are "
          "flagged for investigation, not dropped, and the behavioural detector still sees volume-based recon on "
          "them.",
          "* `low_confidence` and `out_of_distribution` hardly help. Unfamiliar benign traffic is not *far* from the "
          "training data: it resembles known attack traffic on the same port, so the model is confident and the "
          "nearest neighbours are close. Both checks also cost unknowns on known traffic and attacks.", "",
          "## Decision", "",
          f"Active configuration (`config/settings.yaml`, `detection.unknown`): enabled = {active['enabled']}, checks "
          f"{active['checks']}. The low-confidence and out-of-distribution checks are implemented and evaluated but "
          "left off. The active model stays `v2_et_none`; the check only changes how its verdicts are reported.", "",
          "## Hybrid view", "",
          "| Situation | Classifier | Behavioural detector | Result |", "|---|---|---|---|",
          "| Known application, normal traffic | benign | no alert | **known benign** |",
          "| Known application, known attack pattern | attack (service familiar) | maybe | **known attack**: ML alert "
          "and MAPE-K assessment |",
          "| Any application, scan-like volume | any | `flow_burst` / `adaptive_rate` / `slow_scan` | **suspicious "
          "behaviour**: behavioural alert and MAPE-K assessment |",
          "| Unfamiliar application or service | attack verdict → unknown | no alert | **requires investigation**: "
          "shown, no decoy |", "",
          "## Limitations", "",
          "* The service profile is per protocol:port. A new application on a port that is already known inherits "
          "that port's profile.",
          "* Only three applications plus infrastructure exist in the data, and the InfluxDB fold has 196 benign "
          "flows.",
          "* Attacks against a newly deployed application are not *classified* until benign examples of it are added "
          "to training.", ""]
    return "\n".join(L)


def main() -> None:
    cfg = load_config()
    path = get_path("reports_dir", cfg) / "unknown_traffic.json"
    path.with_suffix(".md").write_text(render(json.loads(path.read_text()), cfg["detection"]["unknown"]))
    print("wrote", path.with_suffix(".md"))


if __name__ == "__main__":
    main()
