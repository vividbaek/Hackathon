#!/usr/bin/env bash
guard_command() {
  node src/cli.js scan-command "$*"
}
