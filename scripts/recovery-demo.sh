#!/usr/bin/env bash
set -euo pipefail
bash scripts/demo-reset.sh
node src/cli.js scan-command "rm -rf /" || true
node src/cli.js doctor
