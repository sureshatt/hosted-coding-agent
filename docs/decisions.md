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
table after every change, and the eval runs a positive control. Rules
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

## D3. Gateway and sink on gVisor, each on its own network, routed by the VM

**Decision.** The gateway runs in gVisor on its own network (`fg-egress`,
10.249.0.0/24), the sink in gVisor on its own (`fg-sinknet`, 10.248.0.0/24).
Neither is attached to session bridges. The VM routes the one allowed flow
(runtime → gateway:8443) and nothing else: the session's bridge table drops
every other destination before routing, and Docker's forward chain drops
anything without a matching `DOCKER-USER` ACCEPT, which `fgctl` adds per
session and removes on quarantine or destroy. Source addresses are not
translated, so tokens stay bound to the runtime's address.

The gateway has its own egress policy: DNS to the VM's resolver, HTTPS to
public addresses, replies to sessions. Private ranges, the VM and the Mac
are logged and dropped (GATEWAY_EGRESS_BLOCKED). Before this, the gateway
could reach services on the Mac's localhost through Docker's NAT.

**Why the change.** The first version attached the gateway and sink to
every session bridge while they were running. That ruled out gVisor, and
made the gateway a link between sessions. Tested 2026-11-13: after
`docker network connect` on a running gVisor container, Docker reports
success and `docker inspect` shows the new network, but a server inside
gVisor refuses connections on it; gVisor only sets up interfaces when the
sandbox starts. The failure is silent.

**Second silent failure.** With the forward rules in place, the agent
still could not reach the gateway: Claude Code retried for ten minutes,
with no drop logged and nothing in the gateway log. Docker 29's
direct-routing protection adds a raw `PREROUTING` rule per container on a
NAT network (`-d 10.249.0.2 ! -i br-fg-egress -j DROP`). It runs before
`DOCKER-USER`, so the forward ACCEPT counters stayed at zero. We kept the
protection and added a raw ACCEPT for exactly the same flow, tagged and
removed with the session (`netpolicy._routing_rules`). The alternative,
`gateway_mode_ipv4=nat-unprotected`, would open every port on the gateway
to any routed source. Lesson: the reachability check (the legitimate run)
is as important as the blocking checks.

**Third: blocked, but not seen.** The eval then failed D1 and D2: the
attempt to reach the sink was blocked, but with no log, no alert and no
containment. `nft monitor trace` showed why. Docker loads `br_netfilter`,
which runs the IP `PREROUTING` hooks (and Docker's raw drop) inside the
bridge's prerouting stage, before our bridge `input` chain. Any destination
Docker protects (the sink, other sessions' runtimes) was dropped silently.
Both our tables now hook bridge `prerouting` at priority `filter` (-200),
ahead of `br_netfilter` (0). An attempt that is blocked but not logged
fails the test, because the requirement is to detect and contain, not
only to block.

**Evidence.** The gateway's Python process is not visible on the VM (only
`runsc-sandbox`); inside, the kernel log reads "Starting gVisor". From the
gateway: api.anthropic.com 200; the Mac, the VM and a non-HTTPS internet
port blocked and alerted. Full eval: see `docs/results-reference.md`.

## D4. Revocation through a file, not an admin API

The gateway reads `tokens.json` from a directory the VM mounts read-only
into the gateway container, and re-reads it on every change. The control
plane writes it atomically (write, then rename). There is no admin port for
a session to reach, and revocation takes effect on the next request;
containment checks this by presenting the revoked token and reading the
gateway's reason for rejecting it.

## D5. DNS: no resolver for sessions

Sessions have no name resolution except `/etc/hosts` entries the control
plane writes. Their `resolv.conf` points at the bridge address, so every
lookup reaches the VM, is logged with the session ID and is dropped. This
replaces the logging resolver in the original design: nothing a session
needs requires DNS, and a resolver would be one more path out.
