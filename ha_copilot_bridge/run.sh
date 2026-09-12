#!/usr/bin/with-contenv bashio
set -euo pipefail

SOCKET=/run/tailscale/tailscaled.sock
STATE=/data/tailscaled.state
TAILSCALED_LOG=/data/tailscaled.log
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
  >"${TAILSCALED_LOG}" 2>&1 &

for _ in $(seq 1 30); do
  [[ -S "${SOCKET}" ]] && break
  sleep 1
done

if [[ ! -S "${SOCKET}" ]]; then
  bashio::log.fatal "Tailscale did not start."
  exit 1
fi

bashio::log.info "Authenticating the bridge with Tailscale."
if ! tailscale --socket="${SOCKET}" up \
  --auth-key="${AUTH_KEY}" \
  --hostname="${HOSTNAME}" \
  --accept-dns=false \
  --reset \
  --timeout=60s; then
  bashio::log.error "Tailscale authentication did not complete."
  tail -n 50 "${TAILSCALED_LOG}" || true
  exit 1
fi

# Funnel exposes only the MCP listener. The approval listener is a different,
# unexposed port that is reachable only through Home Assistant ingress.
if ! tailscale --socket="${SOCKET}" funnel --bg 8090; then
  bashio::log.error "Tailscale Funnel could not be enabled."
  tail -n 50 "${TAILSCALED_LOG}" || true
  exit 1
fi

PUBLIC_NAME="$(tailscale --socket="${SOCKET}" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
bashio::log.info "MCP endpoint: https://${PUBLIC_NAME}/mcp"
bashio::log.info "Open the add-on panel in Home Assistant to approve prepared writes."

wait "${BRIDGE_PID}"