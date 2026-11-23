#!/usr/bin/env bash
# One command: run the security eval and save the report.
#   scripts/eval.sh                 deterministic checks + 1 prompt-injection run (if a credential is set up)
#   scripts/eval.sh --agent-runs 5  more prompt-injection runs
#   scripts/eval.sh --skip-agent    deterministic checks only (no credential needed)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
out="results/eval-$(date +%Y%m%d-%H%M%S).md"
set +e
scripts/fgctl eval "$@" | tee "$out"
rc=${PIPESTATUS[0]}
set -e
echo; echo "report saved to $out (exit $rc)"
exit "$rc"
