#!/usr/bin/env bash
set -euo pipefail
node src/cli.js scan-command "git status --short"
