#!/usr/bin/env bash
set -Eeuo pipefail

INTERVAL="${SCAN_INTERVAL:-3600}"
OUT_DIR="/textfile"
OUT_FILE="${OUT_DIR}/trivy_host.prom"
CACHE="${TRIVY_CACHE_DIR:-/cache}"

mkdir -p "$OUT_DIR" "$CACHE"

scan_once() {
  tmp_json="$(mktemp)"
  tmp_prom="$(mktemp)"
  trap 'rm -f "$tmp_json" "$tmp_prom"' RETURN

  echo "[trivy-host-scanner] scanning /host"
trivy fs \
  --scanners vuln \
  --format json \
  --cache-dir "$CACHE" \
  --skip-dirs /host/proc \
  --skip-dirs /host/sys \
  --skip-dirs /host/dev \
  --skip-dirs /host/var/lib/docker \
  --quiet \
  /host > "$tmp_json"
  jq -r '
    [ .Results[]?.Vulnerabilities[]? ]
    | group_by(.Severity)
    | .[]
    | "trivy_host_vulnerabilities{severity=\"" + (.[0].Severity | ascii_downcase) + "\"} " + (length|tostring)
  ' "$tmp_json" > "$tmp_prom"

  {
    echo '# HELP trivy_host_scan_timestamp_seconds Unix timestamp of the latest host filesystem scan.'
    echo '# TYPE trivy_host_scan_timestamp_seconds gauge'
    echo "trivy_host_scan_timestamp_seconds $(date +%s)"
    echo '# HELP trivy_host_vulnerabilities Vulnerabilities found by Trivy in the mounted host filesystem.'
    echo '# TYPE trivy_host_vulnerabilities gauge'
    cat "$tmp_prom"
  } > "${OUT_FILE}.tmp"

  mv "${OUT_FILE}.tmp" "$OUT_FILE"
  echo "[trivy-host-scanner] metrics written to $OUT_FILE"
}

while true; do
  scan_once || echo '[trivy-host-scanner] scan failed; keeping previous metrics'
  sleep "$INTERVAL"
done
