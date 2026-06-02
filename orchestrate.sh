#!/usr/bin/env bash
# Deprecated shell-loop driver. Replaced by a single autonomous Codex mission. Forwards to audit.sh.
exec "$(dirname "$0")/audit.sh" "$@"