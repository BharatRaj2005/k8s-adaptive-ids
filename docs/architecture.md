# Architecture

## 1. Component architecture

```mermaid
flowchart LR
    subgraph host["WSL2 host (Ubuntu 26.04)"]
        direction TB
        tcpdump["tcpdump on cni0<br/>(cap_net_raw via setcap)"]
        cap["Capture service<br/>src/capture/service.py<br/>adaptive windows 5/10/30 s"]
        cfm["CICFlowMeter (existing build)<br/>src/feature_extraction/cicflowmeter.py"]
        det["Per-flow classifier<br/>ExtraTrees (dataset + lab benign)<br/>src/detection/predictor.py"]
        beh["Flow-burst detector<br/>src/detection/behavior.py"]
        db[("SQLite knowledge base<br/>data/ids.sqlite")]
        api["FastAPI backend<br/>src/backend/app.py"]
        mapek["MAPE-K controller<br/>src/deception/controller.py"]
        ui["Streamlit SOC dashboard<br/>frontend/app.py"]
        tcpdump --> cap --> cfm --> det --> db
        det --> beh --> db
        db <--> mapek
        api --- mapek
        api <--> db
        ui -->|HTTP| api
        ui -.->|read-only fallback| db
    end

    subgraph k3s["K3s single-node cluster"]
        direction TB
        subgraph tns["target-apps (existing)"]
            nr["Node-RED :1880"]
            gf["Grafana :3000"]
            ifx["InfluxDB :8086"]
        end
        subgraph trf["ids-traffic"]
            ben["traffic-benign Deployment"]
            rec["recon / decoy-probe Jobs"]
        end
        subgraph dec["ids-deception"]
            d1["decoy-* Deployments + Services<br/>(created at runtime)"]
            sa["ServiceAccount ids-controller<br/>namespace-scoped Role"]
        end
        ben --> nr & gf & ifx
        rec --> nr
        rec --> d1
    end

    cni0(("cni0 bridge")) --- tcpdump
    trf --- cni0
    tns --- cni0
    mapek -->|"create / scale / delete<br/>(ids-controller token)"| d1
    mapek -->|"read pod logs<br/>(interactions)"| d1
```

Isolation and least privilege:

* `ids-traffic` egress is limited by NetworkPolicy to the three target ports, the decoy port and DNS.
* Decoys accept ingress only from `ids-traffic` / `target-apps` and have **no** egress (`egress: []`).
* Decoy pods: non-root UID 65534, read-only root filesystem, all capabilities dropped, no privilege
  escalation, no service-account token, no host namespaces or hostPath, `restricted` Pod Security level.
* The backend uses the `ids-controller` service account: write access only to Deployments/Services in
  `ids-deception`, read-only access to the lab namespaces, nodes and the namespace list. No cluster-admin.

## 2. System workflow

```mermaid
flowchart TD
    A[Traffic generation<br/>benign Deployment, recon Job] --> B[Network monitoring<br/>cni0 bridge]
    B --> C[Packet capture<br/>tcpdump, one process per window]
    C --> D[PCAP file<br/>captures/pcap/*.pcap]
    D --> E{Link type<br/>Ethernet?}
    E -- no --> X[Rejected with explanation<br/>e.g. -i any / SLL]
    E -- yes --> F[CICFlowMeter<br/>per-PCAP staging dir]
    F --> G[Validated flow CSV<br/>captures/flows/*.pcap_Flow.csv]
    G --> H[Preprocessing<br/>schema alignment, inf/NaN, fitted selector + imputer]
    H --> I[ML classification<br/>11 classes + confidence]
    H --> J[Flow-burst analysis<br/>per source and service]
    I --> K[(detections)]
    J --> L[(behavior_alerts)]
    S[Simulated test event<br/>dashboard / API] --> M[(simulated_events)]
    K & L & M --> N[MAPE-K controller]
    N --> O[Decoy deployment<br/>ids-deception]
    O --> P[Attacker interacts with decoy]
    P --> Q[Interaction logging<br/>decoy stdout → pod logs → SQLite]
    Q --> N
    K & L & N & Q --> R[Dashboard]
    DS[Dataset CSVs<br/>offline mode] --> H
```

Processing is window-based: a detection appears one window (5–30 s) plus the measured pipeline time
(< 1 s) after the traffic, not packet by packet.

## 3. MAPE-K loop

```mermaid
flowchart LR
    subgraph M["Monitor"]
        m1["new ML detections<br/>(malicious, act_on_sources)"]
        m2["new flow bursts"]
        m3["new simulated events"]
        m4["decoy status (K8s)"]
        m5["decoy interactions (pod logs)"]
    end
    subgraph A["Analyze"]
        a1["group by source + class"]
        a2["confidence ≥ 0.9 → high"]
        a3["≥ 0.6 → medium: needs ≥ 3 detections<br/>in 300 s or a corroborating burst"]
        a4["< 0.6 → low: monitor<br/>benign → never deploy"]
    end
    subgraph P["Plan"]
        p1["class / burst port → decoy profiles<br/>(config policy)"]
        p2["order profiles by past engagement"]
        p3["deploy · scale · refresh TTL<br/>suppress: limit / cooldown"]
    end
    subgraph E["Execute"]
        e1["create Deployment + Service<br/>from predefined template"]
        e2["scale replicas"]
        e3["remove expired / manual"]
    end
    subgraph K["Knowledge (SQLite)"]
        k1["decisions + reasons + evidence"]
        k2["decoy lifecycle + deploy time"]
        k3["interactions"]
    end
    M --> A --> P --> E --> K
    K -->|"engagement reorders profiles,<br/>extends TTL, drives density"| P
    K -->|"history for repeat checks"| A
```

Housekeeping (status reconciliation, readiness and deployment time, interaction collection, TTL expiry,
engagement-based scaling) runs every cycle even when automatic deception is disabled. The ML model is
never retrained from decoy interactions.
