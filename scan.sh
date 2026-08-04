#!/usr/bin/env bash
set -euo pipefail
SCAN_DIR="${1:-${CODEX_SCAN_DIR:-$PWD}}"
SCAN_DIR="$(cd "$SCAN_DIR" && pwd -P)"
CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
RUN_DIR="$SCAN_DIR/.codex-security"
LOG_FILE="$RUN_DIR/scan.log"
SUMMARY_FILE="$RUN_DIR/summary.md"
RESUME_FILE="$RUN_DIR/resume.env"
PROMPT='Use $codex-security:security-scan to scan this project folder for security vulnerabilities.
This is a non-interactive CLI scan started by the user from this folder.
Authorization:
- You are authorized to use subagents for this scan.
- You are authorized to read files in the scan folder.
- You are authorized to write scan artifacts and reports.
- Do not modify project source code.
Scope:
- Treat the current directory as the scan root, even if it is not a Git repository.
- Keep the scan grounded in code evidence.
- Validate plausible findings where feasible.
- Return only a concise final summary with report paths, finding count, and top findings.'
RESUME_PROMPT='Continue the interrupted Codex Security scan for this project folder.
This is a non-interactive CLI resume started by the user from this folder.
Authorization remains unchanged:
- You are authorized to use subagents for this scan.
- You are authorized to read files in the scan folder.
- You are authorized to write scan artifacts and reports.
- Do not modify project source code.
Resume requirements:
- Reuse existing scan artifacts, ledgers, and reports where they are valid.
- Do not restart completed phases or completed worklist rows unless needed for correctness.
- Continue until the scan is complete.
- Return only a concise final summary with report paths, finding count, and top findings.'
scan_pid=""
find_codex() {
  if command -v codex >/dev/null 2>&1; then
    command -v codex
    return 0
  fi
  for candidate in \
    "$HOME/.local/bin/codex" \
    "$HOME/.codex/bin/codex" \
    "/opt/homebrew/bin/codex" \
    "/usr/local/bin/codex"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}
extract_session_id() {
  if [ -s "$LOG_FILE" ]; then
    sed -n 's/^session id: //p' "$LOG_FILE" | tail -n 1
  fi
}
read_resume_session_id() {
  if [ -s "$RESUME_FILE" ]; then
    sed -n 's/^SESSION_ID=//p' "$RESUME_FILE" | tail -n 1
  fi
}
save_resume_state() {
  local session_id="${1:-}"
  local tmp_file="$RESUME_FILE.tmp"
  if [ -z "$session_id" ]; then
    session_id="$(extract_session_id || true)"
  fi
  if [ -z "$session_id" ]; then
    echo "Interrupted before Codex emitted a session id; no resumable state was saved."
    return 1
  fi
  {
    printf 'SESSION_ID=%s\n' "$session_id"
    printf 'SCAN_DIR=%s\n' "$SCAN_DIR"
    printf 'LOG_FILE=%s\n' "$LOG_FILE"
    printf 'SAVED_AT=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$tmp_file"
  mv "$tmp_file" "$RESUME_FILE"
  echo "Saved resumable session id to: $RESUME_FILE"
}
handle_interrupt() {
  local session_id
  trap - INT TERM
  echo
  echo "Interrupted; stopping the scan..."
  session_id="$(extract_session_id || true)"
  save_resume_state "$session_id" || true
  if [ -n "${scan_pid:-}" ] && kill -0 "$scan_pid" 2>/dev/null; then
    kill -TERM "$scan_pid" 2>/dev/null || true
    wait "$scan_pid" 2>/dev/null || true
  fi
  exit 130
}
format_elapsed() {
  local seconds="$1"
  if [ "$seconds" -ge 3600 ]; then
    printf '%02d:%02d:%02d' "$((seconds / 3600))" "$(((seconds / 60) % 60))" "$((seconds % 60))"
  else
    printf '%02d:%02d' "$((seconds / 60))" "$((seconds % 60))"
  fi
}
latest_log_line() {
  if [ ! -s "$LOG_FILE" ]; then
    printf 'Waiting for Codex output...'
    return
  fi
  tail -n 120 "$LOG_FILE" | awk '
    function clean(raw) {
      gsub(/\r/, " ", raw)
      gsub(/\t/, " ", raw)
      gsub(/[[:space:]]+/, " ", raw)
      sub(/^ /, "", raw)
      sub(/ $/, "", raw)
      return raw
    }
    function noisy(line) {
      return line == "" \
        || line == "Reading additional input from stdin..." \
        || line == "turn interrupted" \
        || line ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T.* (ERROR|WARN|INFO|DEBUG|TRACE) / \
        || line ~ /^warning: Skill descriptions were shortened / \
        || line ~ /^OpenAI Codex v/ \
        || line ~ /^[-]+$/ \
        || line ~ /^(workdir|model|provider|approval|sandbox|reasoning effort|reasoning summaries|session id): / \
        || line ~ /^(user|codex|exec)$/ \
        || line ~ /^\/bin\/zsh -lc / \
        || line ~ /^succeeded in [0-9]+/ \
        || line ~ /^failed in [0-9]+/
    }
    function keep(line) {
      return !noisy(line) && (in_codex \
        || line ~ /^--- Resuming scan / \
        || line ~ /^Wrote [0-9]+ / \
        || line ~ /^Phase [0-9]+ /)
    }
    {
      line = clean($0)
      if (line == "codex") {
        in_codex = 1
        next
      }
      if (line == "exec" || line == "user") {
        in_codex = 0
        next
      }
      if (keep(line)) {
        latest = line
      }
    }
    END {
      if (latest == "") {
        latest = "Scan is running; detailed output is in scan.log."
      }
      if (length(latest) > 120) {
        print substr(latest, 1, 117) "..."
      } else {
        print latest
      }
    }'
}
show_scan_progress() {
  local scan_pid="$1"
  local started_at="$2"
  local elapsed frame line
  local i=0
  local frames=('|' '/' '-' '\')
  if [ -t 1 ]; then
    while kill -0 "$scan_pid" 2>/dev/null; do
      frame="${frames[$((i % ${#frames[@]}))]}"
      i=$((i + 1))
      elapsed="$(format_elapsed "$(($(date +%s) - started_at))")"
      line="$(latest_log_line)"
      printf '\rScanning %s %s elapsed | %s' "$frame" "$elapsed" "$line"
      sleep 0.5
    done
    printf '\r%*s\r' 160 ''
  else
    printf 'Scanning'
    while kill -0 "$scan_pid" 2>/dev/null; do
      printf '.'
      sleep 5
    done
    printf '\n'
  fi
}
case "$SCAN_DIR" in
  "/"|"$HOME"|"/Users"|"/tmp"|"/private/tmp")
    echo "Run this from a specific project folder, not $SCAN_DIR."
    exit 1
    ;;
esac
first_file="$(find "$SCAN_DIR" \
  \( -name .git -o -name node_modules -o -name vendor -o -name dist -o -name build -o -name .codex-security \) -type d -prune \
  -o -type f -print -quit 2>/dev/null || true)"
if [ -z "$first_file" ]; then
  echo "No project files found in $SCAN_DIR."
  exit 1
fi
CODEX_BIN="$(find_codex || true)"
if [ -z "$CODEX_BIN" ]; then
  echo "Installing Codex CLI..."
  curl -fsSL https://chatgpt.com/codex/install.sh | CODEX_NON_INTERACTIVE=1 sh
  export PATH="$HOME/.local/bin:$PATH"
  CODEX_BIN="$(find_codex || true)"
fi
if [ -z "$CODEX_BIN" ]; then
  echo "Codex installed, but this script could not locate the binary."
  echo "Expected it at: $HOME/.local/bin/codex"
  exit 1
fi
if ! "$CODEX_BIN" login status >/dev/null 2>&1 && [ -z "${CODEX_API_KEY:-}" ]; then
  echo "Sign in to Codex..."
  "$CODEX_BIN" login --device-auth
fi
echo "Adding Codex Security plugin..."
"$CODEX_BIN" plugin add codex-security --marketplace openai-curated --json >/dev/null 2>&1 || true
mkdir -p "$RUN_DIR"
resume_session_id=""
resume_mode=0
if [ -s "$RESUME_FILE" ] && [ ! -s "$SUMMARY_FILE" ]; then
  resume_session_id="$(read_resume_session_id || true)"
  if [ -n "$resume_session_id" ]; then
    resume_mode=1
  fi
fi
if [ "$resume_mode" -eq 1 ]; then
  echo "Resuming interrupted Codex Security scan in: $SCAN_DIR"
  echo "Using model: $CODEX_MODEL"
  echo "Session id: $resume_session_id"
  echo "Writing progress log to: $LOG_FILE"
  {
    echo
    echo "--- Resuming scan at $(date -u '+%Y-%m-%dT%H:%M:%SZ') with session $resume_session_id ---"
  } >>"$LOG_FILE"
  trap handle_interrupt INT TERM
  "$CODEX_BIN" exec resume \
    --model "$CODEX_MODEL" \
    --skip-git-repo-check \
    --output-last-message "$SUMMARY_FILE" \
    "$resume_session_id" \
    "$RESUME_PROMPT" 2>>"$LOG_FILE" &
else
  rm -f "$LOG_FILE" "$SUMMARY_FILE" "$RESUME_FILE"
  echo "Starting Codex Security scan in: $SCAN_DIR"
  echo "Using model: $CODEX_MODEL"
  echo "Writing progress log to: $LOG_FILE"
  trap handle_interrupt INT TERM
  "$CODEX_BIN" exec \
    --model "$CODEX_MODEL" \
    --config 'model_reasoning_effort="xhigh"' \
    --cd "$SCAN_DIR" \
    --skip-git-repo-check \
    --sandbox workspace-write \
    --output-last-message "$SUMMARY_FILE" \
    "$PROMPT" 2>"$LOG_FILE" &
fi
scan_pid="$!"
scan_started_at="$(date +%s)"
show_scan_progress "$scan_pid" "$scan_started_at"
if wait "$scan_pid"; then
  trap - INT TERM
  rm -f "$RESUME_FILE"
  echo
  cat "$SUMMARY_FILE"
else
  trap - INT TERM
  echo
  echo "Scan failed. Last log lines:"
  tail -n 80 "$LOG_FILE"
  exit 1
fi