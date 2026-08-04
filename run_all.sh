#!/usr/bin/env bash
# Deprecated entry point. The pipeline now runs one root Codex orchestrator with four
# project-scoped custom subagents. Forwards to audit.sh.
exec "$(dirname "$0")/audit.sh" "$@"
