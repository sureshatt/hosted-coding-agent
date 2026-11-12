# Decisions

Short records of decisions that shape the security of the platform, with the
evidence behind them. Newest last.

## D1. Egress boundary: nftables on the VM side of each session's bridge; runtime on gVisor

**Decision.** Each session gets its own Docker bridge (`br-fg-<id>`). The
runtime joins it on gVisor in its default mode (gVisor's own TCP/IP stack).
The VM, not any container, holds a per-session nftables table in the
`bridge` family that filters every frame entering the bridge from the
runtime's port: allow the model gateway on its one port, log and drop
everything else, and log and drop everything addressed to the VM itself.

The bridge is a normal Docker bridge with NAT disabled, not `--internal`.
On an internal network gVisor has no default route, so an attempt to reach
the internet fails inside the sandbox and is never seen. With a default
route via the VM, every attempt reaches the bridge, is logged with the
session ID, and is dropped. NAT is disabled so nothing would get out even if
the rules were missing. DNS goes to the bridge address through a mounted
`resolv.conf` (Docker's 127.0.0.11 resolver is the sandbox's own loopback
under gVisor) so lookups are logged and dropped too.

**Evidence.** `spikes/bridge-nft/run.sh`, 2026-11-12, fresh VM:

| Attempt from the runtime | Result | Logged |
|---|---|---|
| gateway :8443 | allowed | n/a |
| gateway, other port | blocked | yes |
| sink | blocked | yes |
| internet by IP | blocked | yes |
| DNS query (tunnel) | blocked | yes |
| hostname lookup + HTTPS | blocked | yes |
| VM via bridge address | blocked | yes |
| Mac via Lima host address | blocked | yes |
| positive control (sink allowed by rule) | reached sink | n/a |

**Why not the alternatives.**
- *Enforcer container sharing the runtime's namespace* (`spikes/netns-gvisor/`):
  works only with gVisor's `--network=host`, which hands network syscalls to
  the VM kernel; gVisor's default mode takes over the interface and breaks
  it for later sessions. The rules also sat inside a namespace the runtime
  shares.
- *No network at all* (`--network none` plus a Unix socket to the gateway):
  stronger prevention, but attempts are invisible outside the sandbox.
- *Kubernetes with Cilium and a gVisor RuntimeClass*: the production
  equivalent of this design; too much setup for the timebox.

**Limits.** The rules are only as good as their loading: `fgctl` checks the
table after every change, and the harness runs a positive control. Rules
identify the runtime by "the bridge port that is not the gateway or sink",
captured before the runtime starts. A VM root compromise defeats all of this.

## D2. Host: a Lima VM on macOS, Docker Engine on Linux

The whole platform runs in a Lima VM defined in `infra/lima/fg.yaml`. The VM
is a second isolation boundary (a container escape lands in a disposable VM,
not on the Mac), gives us a real Linux kernel with nftables and gVisor, and
is created and destroyed by script. The only host path the VM sees is this
repository, mounted read-only; Lima's default home-directory mount and all
port forwards to the Mac are disabled. Docker Desktop is not supported: its
VM cannot be configured this way.
