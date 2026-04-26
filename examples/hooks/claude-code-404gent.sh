#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "run" ]; then
  shift
  node src/cli.js run -- "$@"
else
  node src/cli.js scan-prompt "$*"
fi
