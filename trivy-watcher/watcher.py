import json
import os
import subprocess
import threading
from collections import OrderedDict
from datetime import datetime, timezone

import docker
from flask import Flask, jsonify
from prometheus_client import Gauge, start_http_server

app = Flask(__name__)
MAX_RESULTS = int(os.getenv("MAX_RESULTS", "100"))
TIMEOUT = os.getenv("TRIVY_TIMEOUT", "10m")
SCAN_EXISTING = os.getenv("STARTUP_SCAN_EXISTING", "true").lower() == "true"
results = OrderedDict()
lock = threading.Lock()
client = None

containers_scanned = Gauge("trivy_watcher_containers_scanned_total", "Number of container image scans completed.")
vulnerabilities = Gauge("trivy_watcher_vulnerabilities", "Vulnerabilities in the latest scan.", ["container", "image", "severity"])
scan_success = Gauge("trivy_watcher_scan_success", "1 if latest scan succeeded, otherwise 0.", ["container", "image"])


def image_name(container):
    tags = container.image.attrs.get("RepoTags") or []
    return tags[0] if tags else container.image.attrs.get("RepoDigests", [container.image.id])[0]


def run_scan(container_id):
    try:
        container = client.containers.get(container_id)
        name, image = container.name, image_name(container)
        started = datetime.now(timezone.utc).isoformat()
        proc = subprocess.run(
            ["trivy", "image", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", TIMEOUT, image],
            capture_output=True, text=True, timeout=900, check=False,
        )
        if proc.returncode not in (0, 5):
            raise RuntimeError(proc.stderr[-2000:] or f"trivy exit code {proc.returncode}")
        data = json.loads(proc.stdout or "{}")
        counts = {"unknown": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        findings = []
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                sev = (vuln.get("Severity") or "UNKNOWN").lower()
                counts[sev] = counts.get(sev, 0) + 1
                findings.append({
                    "id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": sev,
                    "title": vuln.get("Title"),
                })
        record = {"container_id": container.id, "container": name, "image": image, "scanned_at": started,
                  "success": True, "counts": counts, "vulnerabilities": findings}
        with lock:
            results[container.id] = record
            results.move_to_end(container.id)
            while len(results) > MAX_RESULTS:
                results.popitem(last=False)
        for severity, value in counts.items():
            vulnerabilities.labels(name, image, severity).set(value)
        scan_success.labels(name, image).set(1)
        containers_scanned.inc()
        print(f"[trivy-watcher] scanned {name} ({image}): {counts}", flush=True)
    except Exception as exc:
        print(f"[trivy-watcher] scan failed for {container_id}: {exc}", flush=True)


def event_loop():
    global client
    client = docker.from_env()
    if SCAN_EXISTING:
        for container in client.containers.list():
            threading.Thread(target=run_scan, args=(container.id,), daemon=True).start()
    for event in client.events(decode=True):
        if event.get("Type") == "container" and event.get("Action") in {"start", "restart"}:
            cid = event.get("id")
            if cid:
                threading.Thread(target=run_scan, args=(cid,), daemon=True).start()


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/results")
def get_results():
    with lock:
        return jsonify(list(results.values()))


@app.get("/results/<container_id>")
def get_result(container_id):
    with lock:
        item = results.get(container_id)
    return (jsonify(item), 200) if item else (jsonify({"error": "container not scanned yet"}), 404)


if __name__ == "__main__":
    start_http_server(8086, addr="0.0.0.0")
    threading.Thread(target=event_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8090, threaded=True)
