#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  Admina Governance Sidecar — Cheshire Cat Installer
#
#  Starts the Admina proxy as a Docker sidecar container
#  for Cheshire Cat governance.
#
#  Usage:
#    ./setup.sh              # Install and start sidecar
#    ./setup.sh --uninstall  # Stop sidecar and clean up
#    ./setup.sh --status     # Check sidecar health
# ═══════════════════════════════════════════════════════════
set -e

PROXY_PORT="${ADMINA_PORT:-18790}"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="admina-cheshirecat-sidecar"
CONFIG_FILE="${PLUGIN_DIR}/admina.yaml"

C='\033[0;36m'; G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'; B='\033[1m'

banner() {
  echo ""
  echo -e "${C}═══════════════════════════════════════════════════════════${N}"
  echo -e "${C}  Admina Governance Sidecar for Cheshire Cat${N}"
  echo -e "${C}═══════════════════════════════════════════════════════════${N}"
  echo ""
}

check_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo -e "${R}Error: Docker not found. Install Docker first.${N}"
    exit 1
  }
}

# ── Status ─────────────────────────────────────────────────
if [ "$1" = "--status" ]; then
  if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
    echo -e "${G}Admina sidecar is healthy at ${PROXY_URL}${N}"
    curl -s "${PROXY_URL}/health" | python3 -m json.tool 2>/dev/null || true
  else
    echo -e "${R}Admina sidecar is not responding at ${PROXY_URL}${N}"
  fi
  exit 0
fi

# ── Uninstall ──────────────────────────────────────────────
if [ "$1" = "--uninstall" ]; then
  banner
  echo -e "${Y}Stopping Admina sidecar...${N}"
  docker stop "${CONTAINER_NAME}" 2>/dev/null && \
    echo -e "  ${G}Stopped ${CONTAINER_NAME}${N}" || \
    echo -e "  ${Y}Container not running${N}"
  docker rm "${CONTAINER_NAME}" 2>/dev/null || true
  echo -e "\n${G}Uninstall complete.${N}\n"
  exit 0
fi

# ── Install ────────────────────────────────────────────────
banner
check_docker

# Step 1: Stop any existing sidecar
echo -e "${B}[1/3]${N} Preparing..."
docker stop "${CONTAINER_NAME}" 2>/dev/null || true
docker rm "${CONTAINER_NAME}" 2>/dev/null || true
echo -e "  ${G}Ready${N}"

# Step 2: Start the Admina sidecar container
echo -e "\n${B}[2/3]${N} Starting Admina sidecar on port ${PROXY_PORT}..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p "${PROXY_PORT}:8080" \
  -v "${CONFIG_FILE}:/app/admina.yaml:ro" \
  -e "ADMINA_CONFIG=/app/admina.yaml" \
  -e "LOG_LEVEL=INFO" \
  --add-host=host.docker.internal:host-gateway \
  --health-cmd="curl -sf http://localhost:8080/health || exit 1" \
  --health-interval=10s \
  --health-timeout=5s \
  --health-retries=5 \
  ghcr.io/admina-org/admina:latest \
  >/dev/null

echo -e "  Waiting for health check..."
for i in $(seq 1 30); do
  if curl -sf "${PROXY_URL}/health" >/dev/null 2>&1; then
    echo -e "  ${G}Sidecar is healthy!${N}"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo -e "  ${R}Sidecar didn't start in time.${N}"
    echo -e "  ${R}Check logs: docker logs ${CONTAINER_NAME}${N}"
    exit 1
  fi
  sleep 2
done

# Step 3: Instructions
echo -e "\n${B}[3/3]${N} Configuration"
echo ""
echo -e "  Set in your Cheshire Cat .env or docker-compose:"
echo -e "  ${C}ADMINA_PROXY_URL=${PROXY_URL}${N}"
echo ""
echo -e "  Then copy this plugin into the Cat:"
echo -e "  ${C}cp -r ${PLUGIN_DIR} <cheshire-cat>/plugins/admina-plugin${N}"
echo ""
echo -e "${C}═══════════════════════════════════════════════════════════${N}"
echo -e "  ${G}Admina is now governing your Cheshire Cat${N}"
echo -e ""
echo -e "  Validate: ${Y}POST ${PROXY_URL}/api/v1/validate${N}"
echo -e "  Audit:    ${Y}POST ${PROXY_URL}/api/v1/audit${N}"
echo -e "  Health:   ${Y}${PROXY_URL}/health${N}"
echo -e "${C}═══════════════════════════════════════════════════════════${N}"
echo ""
