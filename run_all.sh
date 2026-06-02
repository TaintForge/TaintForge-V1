#!/usr/bin/env bash
# Deprecated shell-loop driver. The pipeline now runs as ONE autonomous Codex session
# (the agent self-loops; the shell does not re-invoke Codex per module). Forwards to audit.sh.
exec "$(dirname "$0")/audit.sh" "$@"