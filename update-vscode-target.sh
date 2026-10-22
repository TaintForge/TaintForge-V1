#!/usr/bin/env bash
# Check whether targets/vscode-<ver> is still the newest microsoft/vscode release, and
# optionally materialize the newer one.
#
#   ./update-vscode-target.sh            # report only
#   ./update-vscode-target.sh --apply    # create targets/vscode-<new> and seed it
#
# A running campaign is NOT switched automatically: the Code Model, coverage tree and every
# file:line in workspace/findings and leads.json are pinned to the tag under analysis, so the
# new version gets its own target directory and its own workspace.
set -Eeuo pipefail
cd "$(dirname "$0")"

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

CURRENT_DIR="$(ls -d targets/vscode-* 2>/dev/null | sort -V | tail -1 || true)"
[ -n "$CURRENT_DIR" ] || { echo "no targets/vscode-* checkout found" >&2; exit 2; }
CURRENT="${CURRENT_DIR#targets/vscode-}"

echo "local:  $CURRENT  ($CURRENT_DIR)"
LATEST="$(git ls-remote --tags https://github.com/microsoft/vscode 'refs/tags/1.*' \
  | grep -v '\^{}' | awk '{print $2}' | sed 's#refs/tags/##' | sort -V | tail -1)"
[ -n "$LATEST" ] || { echo "could not reach github to list tags" >&2; exit 1; }
echo "latest: $LATEST"

if [ "$CURRENT" = "$LATEST" ]; then
  echo "up to date - nothing to do"
  exit 0
fi

NEWDIR="targets/vscode-$LATEST"
echo "NEWER RELEASE AVAILABLE: $CURRENT -> $LATEST"
if [ "$APPLY" != "1" ]; then
  echo "re-run with --apply to create $NEWDIR and seed it"
  exit 0
fi
[ -e "$NEWDIR" ] && { echo "$NEWDIR already exists" >&2; exit 2; }

# Clone from the local repo first (hardlinked objects, no re-download), then point the new
# checkout back at upstream and pull just the missing objects for the new tag.
echo "== creating $NEWDIR from $CURRENT_DIR =="
git clone --no-checkout --shared "$CURRENT_DIR" "$NEWDIR"
git -C "$NEWDIR" remote set-url origin https://github.com/microsoft/vscode
git -C "$NEWDIR" fetch --tags origin
git -C "$NEWDIR" checkout -q "tags/$LATEST"
git -C "$NEWDIR" log -1 --format='checked out %H  %ci  %d'

echo "== seeding $NEWDIR (archive the old workspace first if a campaign is running) =="
./seed-vscode.sh "$NEWDIR"

cat <<EOF

Next:
  1. stop the current campaign:  touch workspace/_stop; kill \$(cat workspace/_pids); tmux kill-session -t taintforge
  2. archive its workspace:      mv workspace workspace-vscode-$CURRENT-\$(date +%Y%m%d) && mkdir -p workspace
  3. re-seed into the fresh workspace:  ./seed-vscode.sh $NEWDIR
  4. relaunch:                   TARGET=$NEWDIR ./run-vscode.sh
EOF
