#!/usr/bin/env bash
guard_command() {
  node src/cli.js scan-command "$*"
}

grun() {
  node src/cli.js run -- "$@"
}

alias g404run='grun'
