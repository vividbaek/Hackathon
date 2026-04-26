#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

codesign --sign - \
  --entitlements es-daemon.entitlements \
  --force \
  .build/debug/es-daemon
