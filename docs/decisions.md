# Decisions

Short records of decisions that shape the security of the platform, with the
evidence behind them. Newest last.

## D1. Session runtime: gVisor with kernel networking, inside an enforcer-owned namespace

**Decision.** Each session runs as two containers. The *enforcer* owns the
session's network namespace and loads nftables rules (default deny, allow the
model gateway, log every drop). The *runtime* joins that namespace
(`--network container:<enforcer>`) using gVisor with `--network=host`
(Docker runtime `runsc-kernelnet`), with all capabilities dropped.

**Evidence.** `spikes/netns-gvisor/run.sh`, run in a fresh VM (2026-11-10):

| Runtime | Gateway allowed | Sink blocked | Raw IP blocked | Drops logged | Rules survive root in runtime |
|---|---|---|---|---|---|
| runc | yes | yes | yes | yes | yes (no `CAP_NET_ADMIN`) |
| runsc-kernelnet | yes | yes | yes | yes | yes (no `CAP_NET_ADMIN`; gVisor also has no nftables netlink) |
| runsc (default) | first session only | n/a | n/a | no | n/a |

gVisor's default network mode takes over the namespace's interface: the first
container worked and every later container in the same namespace had no
network. It looked "blocked" in testing but was simply broken, and it would
bypass the enforcer's rules rather than obey them. Rejected.

The first spike run also produced a false result: the rules silently failed
to load (`docker exec` without `-i` dropped stdin) and runc reached the sink.
The spike now refuses to continue unless the rules are loaded, and the test
harness will include a positive control for the same reason.

**Trade-off.** With `--network=host`, gVisor passes socket calls to the VM
kernel's network stack, so the network part of the kernel is exposed to the
sandbox; filesystem, process and other syscalls stay inside gVisor. In
production, a microVM (Firecracker or Kata) per session would remove this
trade-off.

**Where drops are logged.** The VM kernel log (`journalctl -k`), enabled by
`net.netfilter.nf_log_all_netns=1`. Session containers cannot read or alter it.

## D2. Host: a Lima VM on macOS, Docker Engine on Linux

The whole platform runs in a Lima VM defined in `infra/lima/fg.yaml`. The VM
is a second isolation boundary (a container escape lands in a disposable VM,
not on the Mac), gives us a real Linux kernel with nftables and gVisor, and
is created and destroyed by script. The only host path the VM sees is this
repository, mounted read-only; Lima's default home-directory mount and all
port forwards to the Mac are disabled. Docker Desktop is not supported: its
VM cannot be configured this way.
