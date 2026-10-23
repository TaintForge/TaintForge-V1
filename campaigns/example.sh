#!/usr/bin/env bash
# Example campaign. Copy to campaigns/<name>.sh and edit; see campaigns/README.md.
#
#   ./seed.sh targets/<app> campaigns/<name>.modules   # once per checkout
#   ./campaigns/<name>.sh                              # run the roles
set -Eeuo pipefail
cd "$(dirname "$0")/.."

TARGET="${TARGET:-targets/example-app}"
URL="${URL:-http://127.0.0.1:8080}"          # drop -u below for a target with no live service
ACCOUNTS="${ACCOUNTS:-.example.accounts.json}"

export TF_BACKEND="${TF_BACKEND:-claude}"     # claude | codex
export TF_MODEL="${TF_MODEL:-claude-opus-5}"  # per-role override: CODEX_CMD_A ... CODEX_CMD_E
export MAX_HOURS="${MAX_HOURS:-12}"
export TF_REUSE_SEED="${TF_REUSE_SEED:-1}"    # seed.sh already ran; don't rebuild per respawn

# The canary must be reachable FROM the target process. For a containerized target that means
# a name the container can resolve and hairpin, not 127.0.0.1.
export SSRF_HOST="${SSRF_HOST:-127.0.0.1}"
export SSRF_PORT="${SSRF_PORT:-9898}"
# No live URL but the lab copy still needs an oracle? Drop -u and set: export TF_CANARY=1

export TAINTFORGE_EXTRA_CONTEXT="TARGET-SPECIFIC NOTES - example-app @ <tag/commit>.

LIVE INSTANCE
  Login: POST /login with user/pass; the CSRF token comes from the <meta name=csrf> tag.
  Accounts: alice and bob are peers (use them for ownership tests), admin holds every role.

EXTRACTOR LIMITS ON THIS STACK
  State here what the call graph cannot see on this language/framework - dynamic dispatch,
  hooks, DI containers, magic methods - so a graph edge is treated as a hint to verify by
  reading, never as a path to report.

PER-MODULE MODELS
  workspace/cm/<name>.json for each entry in campaigns/example.modules. Query with:
    callgraph.py    --model  workspace/cm/<name>.json --sinks
    proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route

DISCLOSURE (C only, on confirmed product vulnerabilities)
  Name this vendor's real issue tracker, release notes and advisory feed here - the ladder in
  AGENTS.md needs to know where to look for THIS project."

exec ./start.sh -u "$URL" --accounts "$ACCOUNTS" "$TARGET"
