#!/usr/bin/env bash
# Run every harness self-test. The gates in write_finding.py, proof_ledger.py and triage.py are
# what make TaintForge a harness rather than a prompt, so they are the thing that must stay
# provably working. Run this after touching any of them.
set -Eeuo pipefail
cd "$(dirname "$0")"

fail=0

echo "== prerequisites =="
python3 -c "import jsonschema" 2>/dev/null \
  && echo "OK   jsonschema present (findings are schema-validated on every write)" \
  || { echo "FAIL jsonschema missing - write_finding.py would skip validation silently"; fail=1; }
python3 -c "import json,sys; json.load(open('schemas/finding.schema.json')); json.load(open('schemas/code_model.schema.json'))" \
  && echo "OK   both schemas parse" || fail=1

echo "== shell syntax =="
for f in audit.sh start.sh seed.sh campaigns/example.sh; do
  bash -n "$f" && echo "OK   $f" || { echo "FAIL $f"; fail=1; }
done

echo "== gate tests =="
for t in .agents/skills/convergence/tests/test_*.py; do
  if python3 "$t" >/dev/null 2>&1; then
    echo "OK   $(basename "$t")"
  else
    echo "FAIL $(basename "$t")"; python3 "$t" 2>&1 | tail -20; fail=1
  fi
done

[ "$fail" = 0 ] && echo "== all harness self-tests passed ==" || echo "== FAILURES above =="
exit "$fail"
