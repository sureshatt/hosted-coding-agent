#!/usr/bin/env bash
# One command: run the security test harness and save the report.
#   scripts/test.sh                 deterministic tests + 1 prompt-injection run (if a credential is set up)
#   scripts/test.sh --agent-runs 5  more prompt-injection runs
#   scripts/test.sh --skip-agent    deterministic tests only (no credential needed)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
out="results/report-$(date +%Y%m%d-%H%M%S).md"
set +e
scripts/fgctl test "$@" | tee "$out"
rc=${PIPESTATUS[0]}
set -e
echo; echo "report saved to $out (exit $rc)"
exit "$rc"
