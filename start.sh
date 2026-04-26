#!/usr/bin/env bash
# 404gent - Dashboard + Policy Server 동시 실행
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 색상
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

cleanup() {
  echo ""
  echo -e "${YELLOW}Shutting down 404gent...${NC}"
  kill "$DASH_PID" "$SERVER_PID" 2>/dev/null
  wait "$DASH_PID" "$SERVER_PID" 2>/dev/null
  echo -e "${GREEN}404gent stopped.${NC}"
}
trap cleanup EXIT INT TERM

echo -e "${CYAN}"
echo "  ⬡  404gent - Multimodal AI Guardrail Runtime"
echo "  ─────────────────────────────────────────────"
echo -e "${NC}"

# 1) Policy Server (port 7404)
echo -e "${CYAN}[1/2]${NC} Starting Policy Server..."
node src/cli.js server &
SERVER_PID=$!
sleep 1

if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo -e "${GREEN}  ✓ Policy Server running on http://127.0.0.1:7404${NC}"
else
  echo -e "${RED}  ✗ Policy Server failed to start${NC}"
fi

# 2) Dashboard (port 4040-4050)
echo -e "${CYAN}[2/2]${NC} Starting Dashboard..."
node src/dashboard.js &
DASH_PID=$!
sleep 2

if kill -0 "$DASH_PID" 2>/dev/null; then
  echo -e "${GREEN}  ✓ Dashboard running${NC}"
else
  echo -e "${RED}  ✗ Dashboard failed to start${NC}"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  404gent is ready!${NC}"
echo -e "  Dashboard:     ${CYAN}http://127.0.0.1:4040${NC}"
echo -e "  Policy Server: ${CYAN}http://127.0.0.1:7404${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all services${NC}"
echo ""

# 두 프로세스 모두 살아있는 동안 대기
while kill -0 "$DASH_PID" 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null; do
  sleep 1
done
