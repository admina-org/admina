#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  Admina — Benchmark Launcher
# ═══════════════════════════════════════════════════════════
#
#  Usage:
#    ./run-benchmark.sh              # default: 500 req, 20 concurrent
#    ./run-benchmark.sh --quick      # smoke:   100 req, 10 concurrent
#    ./run-benchmark.sh --heavy      # stress: 2000 req, 50 concurrent
#    ./run-benchmark.sh -n 1000 -c 30   # custom
#
#  Reports are saved to ./benchmark-reports/
# ═══════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  🦉  Admina — Benchmark Launcher (Heimdall)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 1: Ensure platform is running ────────────────────
echo -e "${YELLOW}[1/3]${NC} Checking if platform is running..."

if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✅ Platform is already running${NC}"
else
    echo -e "  ⏳ Starting platform (docker compose up -d)..."
    docker compose up -d --build
    echo -e "  ⏳ Waiting for proxy to be healthy..."
    for i in $(seq 1 60); do
        if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
            echo -e "  ${GREEN}✅ Platform is ready!${NC}"
            break
        fi
        sleep 2
    done
fi

# ── Step 2: Create reports directory ──────────────────────
mkdir -p benchmark-reports

# ── Step 3: Run benchmark ─────────────────────────────────
ARGS="${@:---requests 500 --concurrency 20}"
echo ""
echo -e "${YELLOW}[2/3]${NC} Launching benchmark with args: ${ARGS}"
echo ""

# Decide: run inside Docker or natively
if command -v python3 &> /dev/null && python3 -c "import httpx" 2>/dev/null; then
    # Run natively (faster, direct access)
    PROXY_URL=http://localhost:8080 \
    REPORT_DIR=./benchmark-reports \
    python3 scripts/benchmark.py $ARGS
else
    # Run via Docker Compose
    docker compose \
        -f docker-compose.yml \
        -f docker-compose.benchmark.yml \
        run --rm benchmark $ARGS
fi

# ── Step 4: Report summary ────────────────────────────────
echo ""
echo -e "${YELLOW}[3/3]${NC} Reports generated:"
echo ""

LATEST_JSON=$(ls -t benchmark-reports/benchmark_*.json 2>/dev/null | head -1)
LATEST_HTML=$(ls -t benchmark-reports/benchmark_*.html 2>/dev/null | head -1)

if [ -n "$LATEST_JSON" ]; then
    echo -e "  📄 JSON:  ${GREEN}${LATEST_JSON}${NC}"
fi
if [ -n "$LATEST_HTML" ]; then
    echo -e "  🌐 HTML:  ${GREEN}${LATEST_HTML}${NC}"
    echo ""
    echo -e "  Open the HTML report in your browser:"
    echo -e "  ${CYAN}open ${LATEST_HTML}${NC}  (macOS)"
    echo -e "  ${CYAN}xdg-open ${LATEST_HTML}${NC}  (Linux)"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Dashboard:  ${YELLOW}http://localhost:3000${NC}"
echo -e "  Grafana:    ${YELLOW}http://localhost:3001${NC}"
echo -e "  Swagger:    ${YELLOW}http://localhost:8080/docs${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
