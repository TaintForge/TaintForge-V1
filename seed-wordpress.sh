#!/usr/bin/env bash
# Seed a WordPress target: whole-repo index + per-module full models + coverage + hypotheses.
# The whole-repo extract is graph-only (>4000 analyzable files), so the per-module models under
# workspace/cm/ are what A/B actually query for sinks and paths.
#
# Usage: ./seed-wordpress.sh [targets/wordpress-develop]
set -Eeuo pipefail
cd "$(dirname "$0")"
TARGET="${1:-targets/wordpress-develop}"
[ -d "$TARGET" ] || { echo "no such target: $TARGET" >&2; exit 2; }
S=.agents/skills
mkdir -p workspace/cm

# name:path pairs - the areas that carry WordPress's security boundaries.
MODULES=(
  "src-all:src"
  "core-includes:src/wp-includes"
  "admin:src/wp-admin"
  "admin-includes:src/wp-admin/includes"
  "rest-api:src/wp-includes/rest-api"
  "blocks:src/wp-includes/blocks"
  "block-supports:src/wp-includes/block-supports"
  "block-bindings:src/wp-includes/block-bindings"
  "block-patterns:src/wp-includes/block-patterns"
  "html-api:src/wp-includes/html-api"
  "interactivity-api:src/wp-includes/interactivity-api"
  "abilities-api:src/wp-includes/abilities-api"
  "ai-client:src/wp-includes/ai-client"
  "php-ai-client:src/wp-includes/php-ai-client"
  "customize:src/wp-includes/customize"
  "widgets:src/wp-includes/widgets"
  "sitemaps:src/wp-includes/sitemaps"
  "style-engine:src/wp-includes/style-engine"
  "requests-http:src/wp-includes/Requests"
  "simplepie:src/wp-includes/SimplePie"
  "ixr-xmlrpc:src/wp-includes/IXR"
  "phpmailer:src/wp-includes/PHPMailer"
  "id3:src/wp-includes/ID3"
  "pomo:src/wp-includes/pomo"
  "text-diff:src/wp-includes/Text"
  "theme-tt5:src/wp-content/themes/twentytwentyfive"
  "js-core:src/js"
  "tools:tools"
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
  if [ "$jobs_running" -ge 6 ]; then wait; jobs_running=0; fi
done
wait

echo "== coverage tree + hypotheses =="
python3 "$S/source-model/scripts/coverage.py" --init "$TARGET"
python3 "$S/hypothesize/scripts/gen_hypotheses.py" --target "$TARGET"
echo "== seed complete for $TARGET =="
