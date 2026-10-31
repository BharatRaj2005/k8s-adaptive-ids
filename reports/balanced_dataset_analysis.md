# Generated dataset: quality report (gen-v1)

Generated 2026-10-31T16:38:02Z by `python -m src.datagen.build` from 54 of 54 planned capture sessions (`data/generated/manifest.json`). Every figure below is counted from the labelled flows.

## Summary

|  | Flows |
|---|---|
| Captured flows (all sessions) | 85,473 |
| Valid labelled flows (trainable) | 48,414 |
| Ambiguous (excluded from training) | 37,059 |
| Discarded (invalid + exact duplicates) | 0 |
| Flows touching the capture edge (kept, flagged) | 287 |
| Failed sessions | 0 |

## Samples per class

| Class | Valid flows | Generator session traffic | Background (benign) |
|---|---|---|---|
| Benign | 42,805 | 3,896 | 38,909 |
| Node-RED Reconnaissance | 5,609 | 5,609 | 0 |

Only Benign and Node-RED Reconnaissance (class 2; the dataset's name for path enumeration, here against all three applications) are generated. No other attack class was produced, by design: see the plan (`docs/dataset_generation_plan.md`).

## Status of every captured flow

| Status | Flows | Share |
|---|---|---|
| generator_dns | 37,051 | 43.3% |
| background_cluster | 25,225 | 29.5% |
| background_generator | 13,684 | 16.0% |
| session_traffic | 9,505 | 11.1% |
| generator_unmatched | 8 | 0.0% |

Ambiguous reasons: 2 connections match (8), DNS lookup of the generator (no independent ground truth) (37,051)

## Samples per application

| Application (by service endpoint) | Class | Valid flows |
|---|---|---|
| grafana | Benign | 2,381 |
| grafana | Node-RED Reconnaissance | 2,088 |
| influxdb | Benign | 3,457 |
| influxdb | Node-RED Reconnaissance | 1,449 |
| nodered | Benign | 2,874 |
| nodered | Node-RED Reconnaissance | 2,072 |
| other | Benign | 34,093 |

`other` = flows not involving an application port (cluster background: DNS, kubelet, API server, ...).

## Samples per benign profile / scanner (generator session traffic)

| Category | Profile / scanner | Tier | Flows |
|---|---|---|---|
| benign | api_consumer | high | 1,000 |
| benign | api_consumer | low | 50 |
| benign | api_consumer | normal | 250 |
| benign | asset_loader | high | 300 |
| benign | asset_loader | low | 19 |
| benign | asset_loader | normal | 160 |
| benign | browse | high | 300 |
| benign | browse | low | 25 |
| benign | browse | normal | 90 |
| benign | burst_refresh | high | 592 |
| benign | burst_refresh | low | 60 |
| benign | burst_refresh | normal | 200 |
| benign | keepalive_client | high | 36 |
| benign | keepalive_client | low | 15 |
| benign | keepalive_client | normal | 9 |
| benign | poller | high | 600 |
| benign | poller | low | 40 |
| benign | poller | normal | 150 |
| recon | head_crawler | high | 489 |
| recon | head_crawler | medium | 300 |
| recon | head_crawler | slow | 70 |
| recon | keepalive_scanner | high | 139 |
| recon | keepalive_scanner | medium | 59 |
| recon | keepalive_scanner | slow | 12 |
| recon | multi_app_sweep | high | 900 |
| recon | multi_app_sweep | medium | 360 |
| recon | multi_app_sweep | slow | 90 |
| recon | seq_wordlist | high | 600 |
| recon | seq_wordlist | medium | 300 |
| recon | seq_wordlist | slow | 70 |
| recon | shuffled_jitter | high | 600 |
| recon | shuffled_jitter | medium | 300 |
| recon | shuffled_jitter | slow | 70 |
| recon | threaded_parallel | high | 800 |
| recon | threaded_parallel | medium | 360 |
| recon | threaded_parallel | slow | 90 |

## Samples per capture session

| Session | Role | Apps | Requests | Conns logged | Conns with flow | Labelled session flows | All flows | Packets |
|---|---|---|---|---|---|---|---|---|
| benign-api_consumer-high-r1 | test | influxdb,nodered | 1,000 | 1,000 | 1,000 | 1,000 | 5,260 | 37,764 |
| benign-api_consumer-low-r1 | train | nodered,grafana | 50 | 50 | 50 | 50 | 1,820 | 21,599 |
| benign-api_consumer-normal-r1 | train | grafana,influxdb | 250 | 250 | 250 | 250 | 2,042 | 26,180 |
| benign-asset_loader-high-r1 | val | influxdb | 450 | 300 | 300 | 300 | 2,089 | 15,182 |
| benign-asset_loader-low-r1 | train | nodered | 60 | 19 | 19 | 19 | 785 | 10,865 |
| benign-asset_loader-normal-r1 | test | grafana | 200 | 160 | 160 | 160 | 2,393 | 23,868 |
| benign-browse-high-r1 | train | influxdb,nodered | 300 | 300 | 300 | 300 | 2,015 | 15,398 |
| benign-browse-low-r1 | test | nodered,grafana | 25 | 25 | 25 | 25 | 610 | 6,537 |
| benign-browse-normal-r1 | val | grafana,influxdb | 90 | 90 | 90 | 90 | 989 | 8,805 |
| benign-burst_refresh-high-r1 | train | influxdb | 600 | 600 | 592 | 592 | 4,073 | 30,355 |
| benign-burst_refresh-low-r1 | test | nodered | 60 | 60 | 60 | 60 | 1,646 | 17,237 |
| benign-burst_refresh-normal-r1 | train | grafana | 200 | 200 | 200 | 200 | 2,660 | 31,897 |
| benign-keepalive_client-high-r1 | test | influxdb,nodered | 900 | 36 | 36 | 36 | 525 | 11,551 |
| benign-keepalive_client-low-r1 | val | nodered,grafana | 40 | 14 | 14 | 15 | 1,100 | 15,204 |
| benign-keepalive_client-normal-r1 | train | grafana,influxdb | 200 | 9 | 9 | 9 | 997 | 20,382 |
| benign-poller-high-r1 | train | nodered,grafana,influxdb | 600 | 600 | 600 | 600 | 3,209 | 62,557 |
| benign-poller-low-r1 | train | nodered,grafana,influxdb | 40 | 40 | 40 | 40 | 592 | 9,048 |
| benign-poller-normal-r1 | test | nodered,grafana,influxdb | 150 | 150 | 150 | 150 | 1,076 | 18,365 |
| recon-head_crawler-high-r1 | train | nodered | 189 | 189 | 189 | 189 | 1,175 | 7,413 |
| recon-head_crawler-high-r2 | train | grafana | 300 | 300 | 300 | 300 | 1,763 | 10,912 |
| recon-head_crawler-medium-r1 | train | influxdb | 150 | 150 | 150 | 150 | 1,742 | 15,471 |
| recon-head_crawler-medium-r2 | test | nodered | 150 | 150 | 150 | 150 | 1,826 | 18,006 |
| recon-head_crawler-slow-r1 | train | grafana | 35 | 35 | 35 | 35 | 1,354 | 14,583 |
| recon-head_crawler-slow-r2 | val | influxdb | 35 | 35 | 35 | 35 | 1,343 | 16,123 |
| recon-keepalive_scanner-high-r1 | train | nodered | 800 | 73 | 73 | 73 | 594 | 7,177 |
| recon-keepalive_scanner-high-r2 | val | grafana | 800 | 66 | 66 | 66 | 538 | 11,143 |
| recon-keepalive_scanner-medium-r1 | train | influxdb | 350 | 30 | 30 | 30 | 842 | 10,011 |
| recon-keepalive_scanner-medium-r2 | train | nodered | 350 | 29 | 29 | 29 | 864 | 11,997 |
| recon-keepalive_scanner-slow-r1 | train | grafana | 70 | 6 | 6 | 6 | 1,013 | 12,174 |
| recon-keepalive_scanner-slow-r2 | test | influxdb | 70 | 6 | 6 | 6 | 1,044 | 13,901 |
| recon-multi_app_sweep-high-r1 | train | nodered,grafana,influxdb | 450 | 450 | 450 | 450 | 2,489 | 15,799 |
| recon-multi_app_sweep-high-r2 | val | nodered,grafana,influxdb | 450 | 450 | 450 | 450 | 2,462 | 15,746 |
| recon-multi_app_sweep-medium-r1 | train | nodered,grafana,influxdb | 180 | 180 | 180 | 180 | 1,782 | 17,207 |
| recon-multi_app_sweep-medium-r2 | train | nodered,grafana,influxdb | 180 | 180 | 180 | 180 | 1,772 | 15,199 |
| recon-multi_app_sweep-slow-r1 | train | nodered,grafana,influxdb | 45 | 45 | 45 | 45 | 1,596 | 17,492 |
| recon-multi_app_sweep-slow-r2 | test | nodered,grafana,influxdb | 45 | 45 | 45 | 45 | 1,526 | 18,633 |
| recon-seq_wordlist-high-r1 | train | nodered | 300 | 300 | 300 | 300 | 1,664 | 10,014 |
| recon-seq_wordlist-high-r2 | test | grafana | 300 | 300 | 300 | 300 | 1,667 | 13,060 |
| recon-seq_wordlist-medium-r1 | train | influxdb | 150 | 150 | 150 | 150 | 1,376 | 11,081 |
| recon-seq_wordlist-medium-r2 | val | nodered | 150 | 150 | 150 | 150 | 1,370 | 11,184 |
| recon-seq_wordlist-slow-r1 | train | grafana | 35 | 35 | 35 | 35 | 901 | 11,252 |
| recon-seq_wordlist-slow-r2 | train | influxdb | 35 | 35 | 35 | 35 | 881 | 8,968 |
| recon-shuffled_jitter-high-r1 | train | nodered,grafana | 300 | 300 | 300 | 300 | 1,667 | 10,070 |
| recon-shuffled_jitter-high-r2 | train | grafana,influxdb | 300 | 300 | 300 | 300 | 1,690 | 12,444 |
| recon-shuffled_jitter-medium-r1 | train | influxdb,nodered | 150 | 150 | 150 | 150 | 1,424 | 11,595 |
| recon-shuffled_jitter-medium-r2 | test | nodered,grafana | 150 | 150 | 150 | 150 | 1,401 | 11,326 |
| recon-shuffled_jitter-slow-r1 | train | grafana,influxdb | 35 | 35 | 35 | 35 | 998 | 11,923 |
| recon-shuffled_jitter-slow-r2 | val | influxdb,nodered | 35 | 35 | 35 | 35 | 944 | 9,583 |
| recon-threaded_parallel-high-r1 | heldout_scanner | nodered,grafana | 400 | 400 | 400 | 400 | 2,114 | 13,599 |
| recon-threaded_parallel-high-r2 | heldout_scanner | grafana,influxdb | 400 | 400 | 400 | 400 | 2,082 | 13,391 |
| recon-threaded_parallel-medium-r1 | heldout_scanner | influxdb,nodered | 180 | 180 | 180 | 180 | 1,346 | 11,956 |
| recon-threaded_parallel-medium-r2 | heldout_scanner | nodered,grafana | 180 | 180 | 180 | 180 | 1,616 | 13,975 |
| recon-threaded_parallel-slow-r1 | heldout_scanner | grafana,influxdb | 45 | 45 | 45 | 45 | 1,359 | 16,506 |
| recon-threaded_parallel-slow-r2 | heldout_scanner | influxdb,nodered | 45 | 45 | 45 | 45 | 1,367 | 14,419 |

*Conns with flow* below *Conns logged* means some logged connections produced no matching flow (see the per-session status counts in the manifest).

## Duplicates

* Exact duplicate rows removed: 0; invalid rows removed: 0.
* Feature-vector duplicates removed inside the training pool: 40 of 26,057 (0.2%); vectors with conflicting labels: 0.
* Evaluation rows whose feature vector also occurs in training (kept; natural distribution): val_natural 14, test_natural 16, heldout_scanner_natural 13.

## Train / validation / test split (whole sessions)

| Set | Sessions | Rows | Generator session flows | Classes |
|---|---|---|---|---|
| train_natural | 29 | 26,017 | 5,032 | Benign 23,045, Node-RED Reconnaissance 2,972 |
| val_natural | 8 | 6,377 | 1,141 | Benign 5,641, Node-RED Reconnaissance 736 |
| test_natural | 11 | 10,971 | 2,082 | Benign 10,320, Node-RED Reconnaissance 651 |
| heldout_scanner_natural | 6 | 5,009 | 1,250 | Benign 3,759, Node-RED Reconnaissance 1,250 |
| train_balanced | 29 | 3,000 | 2,550 | Benign 1,500, Node-RED Reconnaissance 1,500 |

* Held-out scanner: `threaded_parallel`, all of its sessions; never used for training, validation or tuning.
* Held-out application: `influxdb`. 31 sessions touch it; the application fold trains only on the 12 training sessions that never do.
* No session appears in more than one set (checked by the build).

## Balance

| Class | Available (train) | Selected | Target | Shortfall | Sessions | Benign session traffic | Benign background |
|---|---|---|---|---|---|---|---|
| Benign | 23,045 | 1,500 | 1,500 | 0 | 29 | 1,050 | 450 |
| Node-RED Reconnaissance | 2,972 | 1,500 | 1,500 | 0 | 20 | — | — |

Selection is without replacement, spread as evenly as possible across sessions; nothing is duplicated or synthesised. Validation, test and held-out-scanner sets keep their natural class ratio.

