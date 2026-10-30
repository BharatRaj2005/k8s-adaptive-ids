# Target applications

The lab reuses the existing Node-RED, Grafana and InfluxDB deployments in the
`target-apps` namespace instead of deploying duplicates into a new `ids-targets`
namespace (the namespace name is referenced by the traffic generator's URLs and
NetworkPolicy only).

| Service | Image | Port | NodePort | PVC |
|---|---|---|---|---|
| nodered | nodered/node-red:latest | 1880 | 31880 | nodered-data |
| grafana | grafana/grafana:latest | 3000 | 30300 | grafana-data |
| influxdb | influxdb:2.7 | 8086 | 30806 | influx-config, influx-data |

Start / stop (state is kept in the PVCs):

```bash
kubectl -n target-apps scale deployment grafana influxdb nodered --replicas=1
kubectl -n target-apps scale deployment grafana influxdb nodered --replicas=0
```

The traffic generator reaches them only through the in-cluster service names
(`<svc>.target-apps.svc.cluster.local`). No real exploits are run against them.
