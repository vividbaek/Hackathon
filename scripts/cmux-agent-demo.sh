#!/usr/bin/env bash
set -euo pipefail
node src/cli.js scan-prompt "agent should summarize src"
node src/cli.js scan-command "npm test"
node src/cli.js scan-output "tests passed"
