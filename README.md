# Full-Stack Observability & Security Monitoring with Docker

## Services
- Prometheus: http://localhost:9090
- Loki: http://localhost:3100
- Grafana: http://localhost:9000 (admin/admin)
- Node Exporter: http://localhost:9100/metrics
- cAdvisor: http://localhost:8085
- Trivy Watcher API: http://localhost:8090/results
- Trivy Watcher metrics: http://localhost:8086/metrics

## Start
```bash
docker compose up -d --build
docker compose ps
```

## Grafana
Open http://localhost:9000 and sign in with `admin` / `admin`.
Prometheus and Loki are provisioned automatically. If your instructor explicitly requires clicking through the UI manually, add:
- Prometheus: `http://prometheus:9090` and mark it default.
- Loki: `http://loki:3100`.

## Test container scanning
```bash
docker run -d --name test-nginx nginx:latest
curl http://localhost:8090/results | jq
curl http://localhost:8086/metrics | grep trivy_watcher
```

## Useful PromQL
```promql
rate(container_cpu_usage_seconds_total[5m])
container_memory_working_set_bytes
trivy_host_vulnerabilities{severity="critical"}
trivy_watcher_vulnerabilities{severity="critical"}
```

## Useful LogQL
```logql
{container="test-nginx"}
{stream="stdout"}
```

## Notes
The host scanner scans the filesystem mounted at `/host`. This is a filesystem vulnerability scan, not a complete host runtime/security audit. On Docker Desktop, `/host` represents the Linux VM/filesystem exposed to containers rather than necessarily the physical macOS/Windows host.
