#!/usr/bin/env bash
# Seed a VS Code target: whole-repo index + per-module full models + coverage + hypotheses.
# The whole-repo extract is graph-only (>4000 files), so the per-module models under
# workspace/cm/ are what A/B actually query for sinks and paths.
#
# Usage: ./seed-vscode.sh [targets/vscode-<ver>]
set -Eeuo pipefail
cd "$(dirname "$0")"
TARGET="${1:-targets/vscode-1.141.0}"
[ -d "$TARGET" ] || { echo "no such target: $TARGET" >&2; exit 2; }
S=.agents/skills
mkdir -p workspace/cm

# name:path pairs - the areas that carry VS Code's security boundaries.
MODULES=(
  "workspace-trust:src/vs/workbench/services/workspaces"
  "platform-workspace:src/vs/platform/workspace"
  "tasks:src/vs/workbench/contrib/tasks"
  "webview:src/vs/workbench/contrib/webview"
  "exthost-api:src/vs/workbench/api"
  "terminal:src/vs/workbench/contrib/terminal"
  "debug:src/vs/workbench/contrib/debug"
  "electron-main:src/vs/code"
  "server:src/vs/server"
  "url-handler:src/vs/workbench/contrib/url"
  "ext-git:extensions/git"
  "ext-markdown:extensions/markdown-language-features"
  "cli-rust:cli"
  "notebook:src/vs/workbench/contrib/notebook"
  "ext-management:src/vs/platform/extensionManagement"
  "contrib-extensions:src/vs/workbench/contrib/extensions"
  "mcp:src/vs/workbench/contrib/mcp"
  "agent-host:src/vs/platform/agentHost"
  "platform:src/vs/platform"
)

echo "== whole-repo structural index =="
"$S/source-model/scripts/build_code_model.sh" "$TARGET"

echo "== per-module full models (dataflow + sinks + proof ledger) =="
jobs_running=0
for entry in "${MODULES[@]}"; do
  name="${entry%%:*}"; dir="${entry#*:}"
  if [ ! -d "$TARGET/$dir" ]; then echo "SKIP $name ($dir not in this version)"; continue; fi
  (
    if python3 "$S/source-model/scripts/build_code_model.py" "$TARGET/$dir" \
         -o "workspace/cm/$name.json" >"workspace/cm/$name.buildlog" 2>&1; then
      echo "OK   $name"
    else
      echo "FAIL $name (see workspace/cm/$name.buildlog)"
    fi
  ) &
  jobs_running=$((jobs_running + 1))
  if [ "$jobs_running" -ge 8 ]; then wait; jobs_running=0; fi
done
wait

echo "== coverage tree + hypotheses =="
python3 "$S/source-model/scripts/coverage.py" --init "$TARGET"
python3 "$S/hypothesize/scripts/gen_hypotheses.py" --target "$TARGET"
echo "== seed complete for $TARGET =="
