#!/usr/bin/env bash
# Purpose: Generate Nginx deny directives from the JSON IP/CIDR list, test the
# Nginx configuration, then reload Nginx. This changes the live deny include.
# Usage (on the Nginx server, from the deployed repository root):
#   bash scripts/sync-blocked-ips-to-nginx.sh \
#     /path/to/ip-blocking/config/blocked-ips.json \
#     /etc/nginx/blocked-ips.conf
# Arguments: [source-json] [output-include]. The source defaults to the config
# directory beside this project's scripts directory.
#
# Requirements: Linux/systemd, Bash, jq, Nginx, and sudo permission to write the
# include, test Nginx, and reload its service. Source must be a readable JSON
# array of objects with ip fields; review each IP/CIDR before running.
# The active Nginx site/http configuration must already include the output file;
# this script does NOT edit site configs or configure HTTPS. Configure real_ip
# correctly behind a proxy/CDN to avoid denying the proxy instead of visitors.
#
# No dry-run or automatic backup/rollback: the include is overwritten BEFORE
# nginx -t. On a failed test, reload is skipped but the on-disk file stays changed;
# restore a known-good include, test, and reload manually. Back it up first.
# This does not restart Node, reload its in-memory list, or change AWS rules.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON_PATH="${1:-$PROJECT_ROOT/config/blocked-ips.json}"
OUT_PATH="${2:-/etc/nginx/blocked-ips.conf}"

if [[ ! -f "$JSON_PATH" ]]; then
  echo "Blocked IP JSON file not found: $JSON_PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not installed. Install jq first." >&2
  exit 1
fi

jq -r '.[] | select(.ip and (.ip|length>0)) | "deny \(.ip);"' "$JSON_PATH" \
  | sudo tee "$OUT_PATH" > /dev/null

sudo nginx -t
sudo systemctl reload nginx

echo "Synced blocked IPs to nginx and reloaded successfully."
