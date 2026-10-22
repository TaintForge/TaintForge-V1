#!/usr/bin/env bash
# TaintForge campaign: Visual Studio Code (microsoft/vscode 1.141.0), white-box, local lab.
#
# Models: the hunters (A injection, B authz/logic) and D (exploitation) run Mythos 5.1;
# C (triage) and E (reanalysis) run Opus 5.
# Stop: touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge
set -Eeuo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-targets/vscode-1.141.0}"
CLAUDE_BASE="claude -p --output-format stream-json --verbose --dangerously-skip-permissions --model"

export TF_BACKEND=claude
export TF_MODEL="${TF_MODEL:-claude-opus-5}"
export CODEX_CMD_A="${CODEX_CMD_A:-$CLAUDE_BASE claude-mythos-5-1}"
export CODEX_CMD_B="${CODEX_CMD_B:-$CLAUDE_BASE claude-mythos-5-1}"
export CODEX_CMD_D="${CODEX_CMD_D:-$CLAUDE_BASE claude-mythos-5-1}"
export MAX_HOURS="${MAX_HOURS:-12}"
# The code model, coverage tree and hypotheses are seeded once outside the run (the whole-repo
# extract takes minutes on 14k files); reuse them so respawns start analyzing immediately.
export TF_REUSE_SEED="${TF_REUSE_SEED:-1}"

CANARY_HOST="${CANARY_HOST:-127.0.0.1}"
CANARY_PORT="${CANARY_PORT:-9111}"

export TAINTFORGE_DYNAMIC_CONTEXT="VS Code is a desktop application, not a web service, so there is
no live URL. The authorized dynamic lab is this machine only: build or install a disposable copy of
the target under .labs/taintforge-vscode and drive it there. Never modify targets/.

Lab containment rules, no exceptions:
  - Run the lab binary with its own throwaway profile: --user-data-dir and --extensions-dir under
    .labs/taintforge-vscode, plus --disable-telemetry and --disable-updates.
  - Crafted repositories, workspace files, settings, tasks, extensions, notebooks, and documents go
    under .labs/taintforge-vscode/cases/<finding-id>/ and nowhere else.
  - A proof payload must be an inert observable marker - write a file under the case directory,
    print a unique token, or fetch the local canary. Never destructive, never persistent outside
    the case directory, never a reverse shell, never anything that leaves this host.
  - The only network endpoints you may touch are localhost services you started yourself for the
    lab and the out-of-band canary at http://$CANARY_HOST:$CANARY_PORT (canary.py check <token>).
    The canary is the right proof for silent outbound fetches - markdown/link preview, settings
    sync, image resolution, telemetry-like beacons. No other host, ever.
  - probe.py and browser_probe.py still apply to anything the lab serves over HTTP: the local
    vscode-server/tunnel listener, the webview origin, and forwarded ports."

export TAINTFORGE_EXTRA_CONTEXT="TARGET-SPECIFIC THREAT MODEL - microsoft/vscode 1.141.0.

The generic 'pre-auth RCE' objective maps onto VS Code's documented security boundaries as follows.
Rank findings by which boundary they break, not by sink class alone.

Tier 1 - code execution with no user consent (the pre-auth equivalent):
  1. Workspace Trust / Restricted Mode escape. Opening or previewing an UNTRUSTED folder, repo,
     .code-workspace, or file must execute no workspace-controlled code. Hunt every path where
     repository content reaches execution while isTrusted is false: task auto-detection and
     autorun, debug/launch configs, extension activation events and their trust declarations
     (untrustedWorkspaces support in package.json), language servers and linters resolved from
     workspace settings (executable path settings such as git.path, *.validate.executablePath,
     python.defaultInterpreterPath, node paths), workspace-scoped settings that are supposed to be
     restricted, .vscode/*.json parsing, module resolution that prefers workspace node_modules,
     and anything spawned before the trust prompt is answered. This is the highest-value class.
  2. vscode:// and vscode-insiders:// protocol/URI handler reachable from a web page or chat link:
     a single click leading to code execution, arbitrary file write, extension install, folder
     open of a remote/UNC path, or tunnel attach.
  3. Argument injection into spawned processes (git, node, rg, shells, the CLI itself) where the
     attacker controls a repo path, branch, remote, filename, or setting - --upload-pack=,
     --ext:, -c core.*, response files.
  4. Git/SCM repo-controlled execution: .git/config, core.fsmonitor, hooks, .gitattributes
     filters, submodule URLs, credential helpers - triggered by clone, open, or SCM refresh.

Tier 2 - sandbox and isolation breaks that complete a chain:
  5. Webview isolation: vscode-webview:// origin handling, asWebviewUri, localResourceRoots,
     CSP/nonce construction, postMessage origin and handle validation, markdown preview and
     notebook renderer HTML sanitization - any XSS that reaches the webview preload, the
     vscode API handle, or a privileged message handler.
  6. Electron hardening: contextIsolation/sandbox flags, preload surface, allowed navigation and
     window.open/shell.openExternal targets, custom protocol handlers (vscode-file://,
     vscode-resource://) and their path normalization.
  7. Extension-host RPC: the renderer<->exthost and exthost<->server IPC protocol, its message
     framing and deserialization, proposed-API gating, and any handler that trusts an identifier
     it did not mint.

Tier 3 - remote and multi-user surfaces:
  8. vscode-server / Remote-SSH / dev tunnels: connection-token generation and comparison,
     websocket Origin and Host validation, /vscode-remote-resource and static file path
     traversal, port-forwarding auth, and the Rust CLI in cli/ (tunnel registration, update and
     download verification, argument handling).

For each candidate, state explicitly which boundary it crosses and from which starting position
(untrusted workspace / web link / malicious extension / remote attacker / local user). Microsoft
documents that a TRUSTED workspace is allowed to execute code and that extensions run with user
privilege by design - so a trusted-workspace task running a command, or a malicious extension
doing anything, is expected behavior, not a vulnerability. C must settle these against Microsoft
Learn Workspace Trust documentation, the VS Code security issue guidance, MSRC advisories, and
microsoft/vscode issues/PRs before confirming anything.

CODE MODEL - read this before querying it:
  - workspace/CODE_MODEL.json is GRAPH-ONLY. 14410 files exceeds the dataflow threshold, so it
    has symbols, entry points and a global index but NO resolved edges, NO sinks and NO paths.
    Treat it as a directory, not as a taint map.
  - Full per-module models (dataflow + sinks + guards + proof ledger) are pre-built in
    workspace/cm/<name>.json for: workspace-trust, platform-workspace, tasks, webview,
    exthost-api, terminal, debug, electron-main, server, url-handler, ext-git, ext-markdown,
    cli-rust, notebook, ext-management, contrib-extensions, platform. Query them:
      python3 .agents/skills/source-model/scripts/callgraph.py --model workspace/cm/<name>.json --sinks
      python3 .agents/skills/source-model/scripts/callgraph.py --model workspace/cm/<name>.json --trace <sink>
      python3 .agents/skills/source-model/scripts/proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
  - Build any other area the same way and keep it in workspace/cm/ so the next respawn reuses it:
      python3 .agents/skills/source-model/scripts/build_code_model.py targets/vscode-1.141.0/<dir> -o workspace/cm/<name>.json
    Keep each module under ~4000 files or it degrades to graph-only too.
  - The extractor uses tree-sitter for TypeScript/Rust here, but it is still an approximation on
    a codebase this dynamic (DI decorators, registries, proxied exthost RPC, string-keyed
    commands). Resolve the real call target by reading the code; never report a path the graph
    asserts but the source does not.

Useful map of the target: src/vs/workbench/services/workspaces and workspace trust services,
src/vs/platform/* (ipc, protocol, remote, terminal, extensionManagement, tunnel),
src/vs/workbench/api/* (exthost RPC), src/vs/workbench/contrib/{tasks,debug,webview,notebook,
markdown-language-features,terminal}, extensions/{git,github,markdown-language-features,
npm,typescript-language-features,emmet}, remote/, cli/ (Rust), and resources/ for protocol and
Electron wiring."

# audit.sh only starts the canary when a live URL is given; VS Code has none, so start the
# out-of-band listener here and leave its pid where the stop command can find it.
mkdir -p workspace
if ! (exec 3<>/dev/tcp/"$CANARY_HOST"/"$CANARY_PORT") 2>/dev/null; then
  python3 .agents/skills/convergence/scripts/canary.py serve --port "$CANARY_PORT" \
    --log workspace/_canary.log > workspace/_log_canary.txt 2>&1 &
  echo $! > workspace/_canary_pid
  echo "== canary listening on $CANARY_HOST:$CANARY_PORT (pid $(cat workspace/_canary_pid)) =="
else
  echo "== canary already listening on $CANARY_HOST:$CANARY_PORT =="
fi

exec ./start.sh "$TARGET" "$@"
