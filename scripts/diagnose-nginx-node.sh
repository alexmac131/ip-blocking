#!/usr/bin/env bash
# Purpose: Diagnose the local Nginx -> Node/PM2 path, including listener, TLS,
# service logs, and host firewall status. Prints findings without changing
# configuration, restarting services, or modifying cloud network rules.
# Usage (on the server, from the repository root):
#   bash scripts/diagnose-nginx-node.sh
#   bash scripts/diagnose-nginx-node.sh example.com 3030
# Optional arguments are the HTTPS virtual-host name and local Node port.
#
# Requirements: Linux with Bash, systemd (systemctl/journalctl), Nginx, curl,
# iproute2 (ss), awk, sed, and standard GNU system utilities. Run as the normal
# PM2 application user with sudo access for Nginx/listener/log checks. PM2, ufw,
# and lsb_release are optional; their absence is reported or skipped.
# Assumes Node HTTP on 127.0.0.1:<port> and Nginx HTTPS on 127.0.0.1:443, with a
# trusted certificate valid for the chosen hostname. TLS validation is not
# bypassed. The HTTP checks send real GET / requests and may create access logs.
# Cloud security groups/NACLs are not inspected. Exit 1 indicates a failed Nginx
# config test or HTTP/TLS check, not an exhaustive summary of all diagnostics.
# Review output before sharing: it can contain hostnames, IPs, and local paths.
set -uo pipefail

HOST="${1:-example.com}"
PORT="${2:-3030}"

if [[ ! "$HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Usage: $0 [nginx-hostname] [node-port]" >&2
  exit 2
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "Node port must be between 1 and 65535." >&2
  exit 2
fi

section() {
  printf '\n== %s ==\n' "$1"
}

section "System"
date -Is
uname -a
if command -v lsb_release >/dev/null 2>&1; then
  lsb_release -ds
fi

section "Nginx version and configuration test"
nginx -v 2>&1 || true
sudo nginx -t 2>&1
nginx_test_status=$?
if (( nginx_test_status != 0 )); then
  echo "Nginx configuration test failed with status $nginx_test_status."
fi

section "Nginx service"
systemctl --no-pager --full status nginx 2>&1 | sed -n '1,14p'

section "Node listener on port $PORT"
sudo ss -ltnp 2>&1 | awk -v port=":$PORT" 'NR == 1 || index($0, port)'

section "PM2 process status"
if command -v pm2 >/dev/null 2>&1; then
  pm2 status
else
  echo "pm2 command not found for this login user."
fi

section "Active Nginx site and proxy directives"
nginx_dump="$(sudo nginx -T 2>&1)"
nginx_dump_status=$?
printf '%s\n' "$nginx_dump" | awk '
  /^# configuration file / { file = $0 }
  /^[[:space:]]*(listen|server_name|proxy_pass|upstream)[[:space:]]/ {
    print file
    print
  }
'
if (( nginx_dump_status != 0 )); then
  echo "nginx -T returned status $nginx_dump_status; see the configuration-test output above."
fi

section "Local Node HTTP check"
curl --silent --show-error --output /dev/null \
  --write-out 'HTTP %{http_code}; connect=%{time_connect}s; total=%{time_total}s\n' \
  --max-time 5 "http://127.0.0.1:${PORT}/"
node_curl_status=$?
if (( node_curl_status != 0 )); then
  echo "Direct Node check failed with curl status $node_curl_status."
fi

section "Local HTTPS virtual-host check for $HOST"
curl --silent --show-error --output /dev/null \
  --write-out 'HTTP %{http_code}; TLS verify=%{ssl_verify_result}; connect=%{time_connect}s; total=%{time_total}s\n' \
  --max-time 8 --resolve "${HOST}:443:127.0.0.1" "https://${HOST}/"
https_curl_status=$?
if (( https_curl_status != 0 )); then
  echo "HTTPS check failed with curl status $https_curl_status."
  echo "This check uses normal certificate verification; a certificate failure is reported rather than bypassed."
fi

section "Recent Nginx error-level service logs"
sudo journalctl -u nginx -p err -n 30 --no-pager 2>&1

section "Firewall status"
if command -v ufw >/dev/null 2>&1; then
  sudo ufw status verbose 2>&1
else
  echo "ufw is not installed; check the host firewall and cloud security-group rules separately."
fi

cat <<'EOF'

Checks above are read-only. Review output before sharing it; hostnames, IPs,
and local paths may be present. Do not share .env contents, credentials, or
private keys. Cloud firewall/security-group rules are not inspected here.
EOF

if (( nginx_test_status != 0 || node_curl_status != 0 || https_curl_status != 0 )); then
  exit 1
fi
