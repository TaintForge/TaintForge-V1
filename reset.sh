touch workspace/_stop 2>/dev/null
pkill -9 -f "TaintForge-V1/audit.sh"; pkill -9 -f "codex exec"; pkill -9 -f "canary.py"; pkill -9 -f "dashboard.py"
rm -rf workspace