#!/usr/bin/env bash
# Start (if needed) the platform VM and run a command inside it.
# Usage: scripts/vm.sh up | down | shell [cmd...]
set -euo pipefail
VM=fg
REPO="$(cd "$(dirname "$0")/.." && pwd)"

case "${1:-}" in
  up)
    if limactl list -q 2>/dev/null | grep -qx "$VM"; then
      limactl start "$VM" --tty=false >/dev/null 2>&1 || true
    else
      # The repository is the only host path the VM sees, and it is read-only.
      limactl start --name="$VM" --tty=false \
        --set ".mounts=[{\"location\":\"$REPO\",\"mountPoint\":\"/fg\",\"writable\":false}]" \
        "$REPO/infra/lima/fg.yaml"
    fi
    ;;
  down)
    limactl delete --force "$VM"
    ;;
  shell)
    shift
    limactl shell --workdir /fg "$VM" -- "$@"
    ;;
  *)
    echo "usage: $0 up|down|shell [cmd...]" >&2; exit 2 ;;
esac
