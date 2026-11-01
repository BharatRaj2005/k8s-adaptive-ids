# Attack Simulator scenario audit

Each scenario is either (1) a real traffic-generation Job whose packets pass through tcpdump →
CICFlowMeter → ML classification, or (2) a SIMULATED event submitted to the MAPE-K controller only
(no Job, no traffic, no detection row). No ML model or detection architecture was changed.

## Network attack simulations — real traffic (Job → tcpdump → CICFlowMeter → ML)

| Scenario (UI) | generator profile | target | expected class | non-destructive mechanism |
|---|---|---|---|---|
| Recon: sequential | seq_wordlist | Node-RED / Grafana / InfluxDB | 2 | GET/HEAD path enumeration |
| Recon: shuffled | shuffled_jitter | any | 2 | shuffled paths, random method/UA |
| Recon: threaded | threaded_parallel | any | 2 | concurrent path sweep |
| Recon: slow | head_crawler | any | 2 | HEAD-only slow crawl |
| Recon: keepalive | keepalive_scanner | any | 2 | many probes per connection |
| Recon: multi_app | multi_app_sweep | all three | 2 | every path on every app |
| Node-RED RCE | nodered_inject | Node-RED | 3 | POST marker body to admin API (rejected; nothing deployed) |
| Grafana path traversal | grafana_traversal | Grafana | 5 | encoded ../ to a marker file (resolves to nothing) |
| InfluxDB auth bypass | influx_authprobe | InfluxDB | 6 | marker bearer token (reads/writes nothing) |
| Grafana avatar SSRF (NEW) | grafana_ssrf | Grafana | 1 | avatar SSRF to a non-resolvable .invalid marker (no internal service reached) |

## Benign traffic — real traffic (same pipeline), expected class 0

browse, poller, api_client, burst, keepalive — legitimate requests only.

## Host-level simulated events — event-only (controller.submit_simulated_event; no Job / traffic / detection)

| Scenario (UI) | class | why event-only |
|---|---|---|
| Container escape | 4 | runtime escape after a foothold; no app-layer network footprint |
| CVE-2021-30465 (runc symlink) | 7 | runc mount/symlink; runtime only |
| CVE-2022-23648 (containerd) | 9 | containerd CRI host path; runtime only |
| CVE-2019-5736 (runc /proc/self/exe) | 10 | runc binary overwrite; runtime only |
| CVE-2021-25741 (kubelet subPath) | 8 | kubelet / API-server mechanism, not HTTP to an allow-listed app |

These stay event-only on principle: fabricating network traffic for host-/runtime-level
vulnerabilities would violate the project rule "do not fabricate network evidence for host-level
vulnerabilities". They are clearly labelled SIMULATED and excluded from ML detection stats.

## Event-only scenario converted to safe traffic this round

- **CVE-2020-13379 (class 1, Grafana avatar SSRF)** was previously absent from the simulator. It is
  genuinely application-layer and feasible to generate safely: the avatar SSRF request shape is sent
  with a guaranteed non-resolvable `.invalid` (and loopback:1) marker target, so Grafana reaches no
  internal service. Implemented as the `grafana_ssrf` profile / "Grafana avatar SSRF" scenario.
  Live check: 80 requests → 3,827 packets → 619 flows → classified.
  Note: reliable lab detection is established only for classes 0, 2, 3, 5, 6; the model does **not**
  reliably classify class 1, and the Live Monitoring expected-vs-actual panel shows this honestly
  (the generated SSRF traffic was mostly predicted Benign).
- The remaining event-only classes (4, 7, 8, 9, 10) have no safe, distinct app-layer representation
  within the lab's allow-listed HTTP applications and remain simulated events.
