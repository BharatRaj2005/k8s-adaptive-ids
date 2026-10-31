"""kubectl helpers for dataset generation (argument lists only, never shell strings)."""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from typing import Any

import yaml

from src.datagen.plan import Session
from src.utils.config import project_path

ENV = {**os.environ, "KUBECONFIG": os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))}


class KubeError(RuntimeError):
    pass


def kubectl(*args: str, stdin: str | None = None, timeout: float = 60) -> str:
    proc = subprocess.run(["kubectl", *args], env=ENV, input=stdin, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise KubeError(f"kubectl {' '.join(args[:4])}: {proc.stderr.strip()[-400:]}")
    return proc.stdout


def kjson(*args: str) -> dict[str, Any]:
    return json.loads(kubectl(*args, "-o", "json"))


def job_name(session_id: str) -> str:
    return ("datagen-" + re.sub(r"[^a-z0-9-]", "-", session_id.lower()))[:63].rstrip("-")


def sync_script(dcfg: dict[str, Any]) -> None:
    """Create or update the generator ConfigMap from the script in the repository."""
    k = dcfg["kubernetes"]
    script = project_path(k["script"])
    manifest = kubectl("-n", k["namespace"], "create", "configmap", k["configmap"],
                       f"--from-file={script.name}={script}", "--dry-run=client", "-o", "yaml")
    cm = yaml.safe_load(manifest)
    cm["metadata"]["labels"] = {"app": "traffic-generator", "mode": "datagen"}
    kubectl("apply", "-f", "-", stdin=yaml.safe_dump(cm))


def job_manifest(s: Session, dcfg: dict[str, Any]) -> dict[str, Any]:
    k, lim = dcfg["kubernetes"], dcfg["limits"]
    job = copy.deepcopy(yaml.safe_load(project_path(k["job_template"]).read_text()))
    name = job_name(s.session_id)
    job["metadata"]["name"] = name
    job["metadata"]["namespace"] = k["namespace"]
    job["metadata"]["labels"]["datagen-session"] = name
    job["spec"]["activeDeadlineSeconds"] = int(lim["max_session_seconds"]) + 30
    job["spec"]["template"]["metadata"]["labels"]["datagen-session"] = name
    pod = job["spec"]["template"]["spec"]
    pod["volumes"][0]["configMap"]["name"] = k["configmap"]
    env = pod["containers"][0]["env"]
    env += [{"name": key, "value": val} for key, val in s.env.items()]
    return job


def app_endpoints(dcfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """ClusterIP and ready pod IPs of every allowed application (pod IPs are what cni0 shows)."""
    out = {}
    for app, c in dcfg["apps"].items():
        svc = kjson("-n", c["namespace"], "get", "service", c["service"])
        pods = kjson("-n", c["namespace"], "get", "pods", "-l", c["pod_selector"])["items"]
        out[app] = {"port": c["port"], "cluster_ip": svc["spec"].get("clusterIP"),
                    "pod_ips": sorted(p["status"]["podIP"] for p in pods
                                      if p["status"].get("phase") == "Running" and p["status"].get("podIP"))}
    return out


def pod_ip_map() -> dict[str, str]:
    """pod IP -> namespace/name for every non-host-network pod (background attribution in reports)."""
    out = {}
    for p in kjson("get", "pods", "-A")["items"]:
        ip = p["status"].get("podIP")
        if ip and not p["spec"].get("hostNetwork"):
            out[ip] = f"{p['metadata']['namespace']}/{p['metadata']['name']}"
    return out


def selector_ips(namespace: str, selector: str) -> list[str]:
    pods = kjson("-n", namespace, "get", "pods", "-l", selector)["items"]
    return sorted(p["status"]["podIP"] for p in pods if p["status"].get("podIP"))


def active_datagen_jobs(namespace: str) -> list[str]:
    jobs = kjson("-n", namespace, "get", "jobs", "-l", "mode=datagen")["items"]
    return [j["metadata"]["name"] for j in jobs
            if not (j.get("status", {}).get("succeeded") or j.get("status", {}).get("failed"))]
