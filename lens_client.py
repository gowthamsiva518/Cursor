"""
Lens / Kubernetes client for Bot Engine restart detection.

Uses kubectl (subprocess) to get pod data -- same data as Lens Workloads → Pods.
Falls back to the Python kubernetes library if kubectl is not available.

Configure via environment:
  KUBE_CONFIG_PATH      - path to kubeconfig file (default: ~/.kube/config)
  KUBE_CONTEXT          - kubeconfig context name (default: current-context)
  KUBE_NAMESPACE        - namespace to search (default: all namespaces)
  KUBE_POD_FILTER       - substring to match pod names (e.g. bot-engine, stream-server)
  KUBE_LABEL_SELECTOR   - label selector (e.g. app=bot-engine)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any


def _find_kubectl() -> str | None:
    """Find kubectl binary."""
    path = shutil.which("kubectl")
    if path:
        return path
    for candidate in [r"C:\kubectl\kubectl.exe", "/usr/local/bin/kubectl", "/usr/bin/kubectl"]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _age_str(created_at: str | None) -> str:
    if not created_at:
        return "unknown"
    try:
        ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - ts
        total_secs = int(delta.total_seconds())
        if total_secs < 0:
            return "0s"
        if total_secs < 60:
            return f"{total_secs}s"
        if total_secs < 3600:
            return f"{total_secs // 60}m"
        if total_secs < 86400:
            return f"{total_secs // 3600}h {(total_secs % 3600) // 60}m"
        days = total_secs // 86400
        hours = (total_secs % 86400) // 3600
        return f"{days}d {hours}h"
    except Exception:
        return "unknown"


def _run_kubectl(args: list[str], timeout: int = 90) -> dict[str, Any] | None:
    """Run kubectl with JSON output. Returns parsed JSON or None on failure."""
    kubectl = _find_kubectl()
    if not kubectl:
        return None

    cmd = [kubectl] + args + ["-o", "json"]

    context = os.environ.get("KUBE_CONTEXT", "").strip()
    if context:
        cmd += ["--context", context]

    config_path = os.environ.get("KUBE_CONFIG_PATH", "").strip()
    if config_path:
        cmd += ["--kubeconfig", config_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return {"error": result.stderr.strip() or f"kubectl exited with code {result.returncode}"}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "kubectl timed out after " + str(timeout) + "s"}
    except json.JSONDecodeError:
        return {"error": "kubectl returned invalid JSON"}
    except Exception as e:
        return {"error": str(e)}


def query_pod_restarts(
    namespace: str | None = None,
    pod_filter: str | None = None,
    label_selector: str | None = None,
    time_minutes: int | None = None,
) -> dict[str, Any] | None:
    """
    Query Kubernetes for bot engine pod restarts (same data as Lens → Workloads → Pods).
    Uses kubectl subprocess (bypasses firewall issues with direct API calls).
    Returns None when kubectl is not found.
    """
    ns = namespace or os.environ.get("KUBE_NAMESPACE", "").strip() or None
    pf = pod_filter or os.environ.get("KUBE_POD_FILTER", "").strip() or None
    ls = label_selector or os.environ.get("KUBE_LABEL_SELECTOR", "").strip() or None

    cmd = ["get", "pods"]
    if ns:
        cmd += ["-n", ns]
    else:
        cmd += ["--all-namespaces"]
    if ls:
        cmd += ["-l", ls]

    data = _run_kubectl(cmd)
    if data is None:
        return None
    if "error" in data and "items" not in data:
        return {"pods": [], "total_restarts": 0, "pods_with_restarts": 0, "error": data["error"]}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=time_minutes) if time_minutes else None

    pods = []
    for item in data.get("items", []):
        metadata = item.get("metadata") or {}
        status = item.get("status") or {}
        name = metadata.get("name", "")

        if pf and not name.lower().startswith(pf.lower()):
            continue

        created_at = metadata.get("creationTimestamp")
        age = _age_str(created_at)

        containers_info = []
        total_restart = 0
        last_restart_at = None

        for cs in status.get("containerStatuses") or []:
            restarts = cs.get("restartCount", 0)
            total_restart += restarts

            container_last_restart = None
            last_state = cs.get("lastState") or {}
            terminated = last_state.get("terminated") or {}
            finished = terminated.get("finishedAt")
            if finished:
                container_last_restart = finished
                if last_restart_at is None or finished > (last_restart_at or ""):
                    last_restart_at = finished

            state_info = cs.get("state") or {}
            state = "running" if "running" in state_info else "terminated" if "terminated" in state_info else "waiting" if "waiting" in state_info else "unknown"

            containers_info.append({
                "name": cs.get("name", ""),
                "restart_count": restarts,
                "ready": cs.get("ready", False),
                "state": state,
                "last_restart_at": container_last_restart,
            })

        if cutoff:
            created_dt = None
            if created_at:
                try:
                    created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                except Exception:
                    pass
            if total_restart == 0:
                if created_dt and created_dt > cutoff:
                    pass  # new pod — include
                else:
                    continue
            elif last_restart_at:
                try:
                    lr_dt = datetime.fromisoformat(last_restart_at.replace("Z", "+00:00"))
                    if lr_dt < cutoff and (not created_dt or created_dt < cutoff):
                        continue
                except Exception:
                    pass

        phase = status.get("phase", "Unknown")

        pods.append({
            "name": name,
            "namespace": metadata.get("namespace", ""),
            "age": age,
            "restart_count": total_restart,
            "status": phase,
            "containers": containers_info,
            "created_at": created_at,
            "last_restart_at": last_restart_at,
        })

    pods.sort(key=lambda p: p["restart_count"], reverse=True)
    total_restarts = sum(p["restart_count"] for p in pods)
    pods_with_restarts = sum(1 for p in pods if p["restart_count"] > 0)

    return {
        "pods": pods,
        "total_restarts": total_restarts,
        "pods_with_restarts": pods_with_restarts,
    }


def check_k8s_connection() -> bool:
    """Return True if kubectl can reach the cluster."""
    data = _run_kubectl(["get", "namespaces", "--limit=1"], timeout=20)
    if data is None:
        return False
    return "error" not in data
