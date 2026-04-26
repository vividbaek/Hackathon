#!/bin/bash

# LLM 프로바이더 전환 스크립트
# Usage: switch-model.sh [glm|mini|claude]
#   glm   - GLM (ZhipuAI) API로 전환 (Claude Code + pipeline)
#   mini  - MiniMax API로 전환 (Claude Code + pipeline)
#   claude — Anthropic 공식 API로 전환 (Claude Code만)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$REPO_ROOT/.claude"
TARGET_FILE="$CONFIG_DIR/settings.local.json"
ENV_FILE="$REPO_ROOT/foreign-stock-pipeline/.env"

# ── .env LLM 블록 업데이트 헬퍼 ─────────────────────────────────────────────
update_env_llm() {
    local api_key="$1"
    local base_url="$2"
    local model="$3"

    if [ ! -f "$ENV_FILE" ]; then
        echo "Warning: $ENV_FILE not found, skipping .env update."
        return
    fi

    # 기존 GLM_API_KEY / GLM_BASE_URL / GLM_MODEL 라인을 새 값으로 교체
    # (주석 처리된 라인은 그대로 두고, 마지막 활성 라인만 업데이트)
    python3 - "$ENV_FILE" "$api_key" "$base_url" "$model" << 'PYEOF'
import sys, re

env_path = sys.argv[1]
api_key  = sys.argv[2]
base_url = sys.argv[3]
model    = sys.argv[4]

with open(env_path, "r") as f:
    lines = f.readlines()

keys_to_set = {
    "GLM_API_KEY":  api_key,
    "GLM_BASE_URL": base_url,
    "GLM_MODEL":    model,
}
updated = {k: False for k in keys_to_set}
result = []

for line in lines:
    stripped = line.strip()
    # 주석 라인은 그대로
    if stripped.startswith("#"):
        result.append(line)
        continue
    matched = False
    for key, val in keys_to_set.items():
        if re.match(rf'^{key}\s*=', stripped):
            result.append(f"{key}={val}\n")
            updated[key] = True
            matched = True
            break
    if not matched:
        result.append(line)

# 없는 키는 파일 끝에 추가
for key, val in keys_to_set.items():
    if not updated[key]:
        result.append(f"{key}={val}\n")

with open(env_path, "w") as f:
    f.writelines(result)

print(f"  .env updated: GLM_BASE_URL={base_url} / GLM_MODEL={model}")
PYEOF
}

read_token() {
    local env_name="$1"
    local placeholder="$2"
    local prompt="$3"
    local token="${!env_name:-}"

    if [ -z "$token" ]; then
        read -rsp "$prompt: " token
        echo ""
    fi

    if [ -z "$token" ] || [ "$token" = "$placeholder" ]; then
        echo "Error: missing token. Set $env_name or enter a real token." >&2
        exit 1
    fi

    printf "%s" "$token"
}

write_claude_token() {
    local path="$1"
    local token="$2"

    python3 - "$path" "$token" << 'PYEOF'
import json, sys

path = sys.argv[1]
token = sys.argv[2]
with open(path) as f:
    data = json.load(f)
data.setdefault("env", {})["ANTHROPIC_AUTH_TOKEN"] = token
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PYEOF
}

# ── 프로바이더 전환 후 PM2 프로세스 재시작 ───────────────────────────────────
restart_llm_processes() {
    echo "  PM2 재시작: invest-paper-trader, invest-swing-trader, invest-agent-py ..."
    pm2 restart invest-paper-trader invest-swing-trader invest-agent-py 2>/dev/null | grep -E "online|error" || true
}

# ── 메인 로직 ────────────────────────────────────────────────────────────────
case "$1" in
    glm)
        # Claude Code 설정
        if [ ! -f "$CONFIG_DIR/settings.glm.json" ]; then
            echo "Error: settings.glm.json not found." && exit 1
        fi
        GLM_TOKEN="$(read_token GLM_API_KEY GLM_API_KEY_HERE "GLM API Token")"
        cp "$CONFIG_DIR/settings.glm.json" "$TARGET_FILE"
        write_claude_token "$TARGET_FILE" "$GLM_TOKEN"
        echo "[1/2] Claude Code → GLM (ZhipuAI)"

        # .env 업데이트
        echo "[2/2] .env LLM 설정 업데이트"
        update_env_llm \
            "$GLM_TOKEN" \
            "https://api.z.ai/api/anthropic" \
            "glm-4.5-air"

        echo ""
        echo "✓ 전환 완료: GLM (ZhipuAI) — glm-4.5-air"
        ;;

    mini)
        # Claude Code 설정
        if [ ! -f "$CONFIG_DIR/settings.minimax.json" ]; then
            echo "Error: settings.minimax.json not found." && exit 1
        fi

        # 토큰 확인
        MINI_TOKEN=$(grep -o '"ANTHROPIC_AUTH_TOKEN": "[^"]*"' "$CONFIG_DIR/settings.minimax.json" | cut -d'"' -f4)
        if [ "$MINI_TOKEN" = "MINIMAX_TOKEN_HERE" ]; then
            MINI_TOKEN="${MINIMAX_API_KEY:-}"
        fi
        if [ -z "$MINI_TOKEN" ] || [ "$MINI_TOKEN" = "MINIMAX_TOKEN_HERE" ]; then
            echo "경고: settings.minimax.json에 실제 MiniMax 토큰이 없습니다."
            echo "  $CONFIG_DIR/settings.minimax.json 파일의 ANTHROPIC_AUTH_TOKEN을 먼저 설정하세요."
            echo ""
            read -rp "토큰을 지금 입력하시겠습니까? (y/N): " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                read -rsp "MiniMax API Token: " MINI_TOKEN
                echo ""
            else
                echo "중단. 토큰 설정 후 다시 실행하세요."
                exit 1
            fi
        fi
        cp "$CONFIG_DIR/settings.minimax.json" "$TARGET_FILE"
        write_claude_token "$TARGET_FILE" "$MINI_TOKEN"
        echo "[1/2] Claude Code → MiniMax"

        # .env 업데이트
        echo "[2/2] .env LLM 설정 업데이트"
        MINI_BASE=$(grep -o '"ANTHROPIC_BASE_URL": "[^"]*"' "$CONFIG_DIR/settings.minimax.json" | cut -d'"' -f4)
        MINI_MODEL="abab6.5s-chat"
        update_env_llm "$MINI_TOKEN" "$MINI_BASE" "$MINI_MODEL"

        echo ""
        echo "✓ 전환 완료: MiniMax — $MINI_MODEL"
        ;;

    claude)
        if [ ! -f "$CONFIG_DIR/settings.claude.json" ]; then
            echo "Error: settings.claude.json not found." && exit 1
        fi
        cp "$CONFIG_DIR/settings.claude.json" "$TARGET_FILE"
        echo "✓ 전환 완료: Anthropic Claude (공식 API)"
        echo "  Note: pipeline(paper_trader/swing_trader)은 별도 설정 필요"
        ;;

    status)
        echo "=== 현재 Claude Code 설정 ==="
        python3 -c "
import json
with open('$TARGET_FILE') as f: d = json.load(f)
env = d.get('env', {})
print('  BASE_URL:', env.get('ANTHROPIC_BASE_URL', '(Anthropic 기본)'))
print('  MODEL:', env.get('ANTHROPIC_DEFAULT_SONNET_MODEL', '(Claude 기본)'))
" 2>/dev/null || echo "  (설정 파일 없음)"
        echo ""
        echo "=== pipeline .env LLM 설정 ==="
        grep -E "^GLM_(API_KEY|BASE_URL|MODEL)=" "$ENV_FILE" 2>/dev/null || echo "  (설정 없음)"
        ;;

    *)
        echo "Usage: $0 [glm|mini|claude|status]"
        echo ""
        echo "  glm    — GLM (ZhipuAI, glm-4.5-air) — 기본값"
        echo "  mini   — MiniMax (MiniMax-M2.7, Anthropic 호환)"
        echo "  claude — Anthropic 공식 Claude"
        echo "  status — 현재 설정 확인"
        exit 1
        ;;
esac
