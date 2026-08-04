#!/usr/bin/env bash
# Deprecated entry point. audit.sh now runs one root Codex orchestrator with custom subagents.
exec "$(dirname "$0")/audit.sh" "$@"
