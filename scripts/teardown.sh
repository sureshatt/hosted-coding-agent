#!/usr/bin/env bash
# Remove everything: the VM holds all sessions, images, evidence and the
# stored credential, so deleting it leaves nothing behind on the host
# except reports saved under results/.
#   scripts/teardown.sh --keep-vm   destroy sessions only, keep the VM
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" == "--keep-vm" ]]; then
  for s in $(scripts/fgctl status | awk '/user=/{print $1}'); do scripts/fgctl destroy "$s"; done
  exit 0
fi
scripts/vm.sh down
echo "VM deleted"
