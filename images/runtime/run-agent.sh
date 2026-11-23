#!/bin/sh
# Entry point of a session runtime.
#   run-agent agent "<task>"   run Claude Code on the task, non-interactively
#   run-agent shell "<cmd>"    run a shell command (used by the eval to
#                              act as an already-compromised agent)
#
# Claude Code runs with permission prompts disabled: nobody is there to answer
# them, and they are not a security boundary here. The boundary is the
# sandbox, the egress policy and the gateway, all outside this container.
set -eu
mode="${1:-}"; shift || true
case "$mode" in
  agent)
    exec claude -p "$1" \
      --dangerously-skip-permissions \
      --output-format stream-json --verbose \
      ${FG_MODEL:+--model "$FG_MODEL"} ;;
  shell)
    exec sh -c "$1" ;;
  *)
    echo "usage: run-agent agent <task> | shell <cmd>" >&2; exit 2 ;;
esac
