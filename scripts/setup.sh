#!/usr/bin/env bash
# One command to stand up the platform: VM, images, gateway, sink, detector.
#
#   scripts/setup.sh                      keeps a stored credential; mock model if there is none
#   FG_UPSTREAM_MOCK=1 scripts/setup.sh   force the mock model
#   FG_UPSTREAM_TOKEN=... scripts/setup.sh   real model for agent runs:
#       a Claude subscription token (`claude setup-token`, starts sk-ant-oat)
#       or an Anthropic API key. It is piped into the VM on stdin, stored
#       root-only, and given only to the gateway container; sessions never see it.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v limactl >/dev/null || { echo "Lima is required: brew install lima" >&2; exit 1; }

scripts/vm.sh up
if [[ -n "${FG_UPSTREAM_TOKEN:-}" ]]; then
  printf '%s' "$FG_UPSTREAM_TOKEN" | scripts/fgctl setup --credential-from-stdin
elif [[ -n "${FG_UPSTREAM_MOCK:-}" ]]; then
  scripts/fgctl setup --mock
else
  scripts/fgctl setup
fi
scripts/fgctl status
