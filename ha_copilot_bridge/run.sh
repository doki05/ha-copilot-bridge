#!/usr/bin/with-contenv bashio
set -euo pipefail

SOCKET=/run/tailscale/tailscaled.sock
STATE=/data/tailscaled.state
AUTH_KEY="$(bashio::config 'tailscale_auth_key')"
HOSTNAME="$(bashio::config 'tailscale_hostname')"

if [[ -z "${AUTH_KEY}" || -z "${HOSTNAME}" ]]; then
  bashio::log.fatal "Tailscale authentication key and hostname are required."
  exit 1
fi

mkdir -p /run/tailscale

bashio::log.info "Starting the HA Copilot Bridge."
python3 /app/server.py &
BRIDGE_PID=$!

cleanup() {
  kill "${BRIDGE_PID}" 2>/dev/null || true
}
trap cleanup EXIT

tailscaled \
  --state="${STATE}" \
  --socket="${SOCKET}" \
  --tun=userspace-networking \
  >/dev/null 2>&1 &

for _ in $(seq 1 30); do
  [[ -S "${SOCKET}" ]] && break
  sleep 1
done

if [[ ! -S "${SOCKET}" ]]; then
  bashio::log.fatal "Tailscale did not start."
  exit 1
fi

tailscale --socket="${SOCKET}" up \
  --auth-key="${AUTH_KEY}" \
  --hostname="${HOSTNAME}" \
  --accept-dns=false \
  --reset >/dev/null

# Funnel exposes only the MCP listener. The approval listener is a different,
# unexposed port that is reachable only through Home Assistant ingress.
tailscale --socket="${SOCKET}" funnel --bg 8090 >/dev/null

PUBLIC_NAME="$(tailscale --socket="${SOCKET}" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
bashio::log.info "MCP endpoint: https://${PUBLIC_NAME}/mcp"
bashio::log.info "Open the add-on panel in Home Assistant to approve prepared writes."

wait "${BRIDGE_PID}"
