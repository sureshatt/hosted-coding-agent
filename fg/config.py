"""Fixed locations and names. Everything here lives inside the VM."""
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent          # read-only mount of this repo

STATE = Path("/var/lib/fg")                            # root-only, never mounted into sessions
REGISTRY_DB = STATE / "registry.db"
EVIDENCE = STATE / "evidence"                          # hash-chained, append-only logs
SNAPSHOTS = EVIDENCE / "snapshots"
SECRETS = STATE / "secrets"                            # upstream model credential
GATEWAY_STATE = STATE / "gateway"                      # tokens.json, mounted read-only into the gateway
LOGS = Path("/var/log/fg")                             # gateway and sink write here; detector reads
DELIVERY = STATE / "delivery"                          # queue/, verdicts/, work/
GIT_REMOTE = STATE / "git-remote"                      # bare repos standing in for GitHub

# Images
INFRA_IMAGE = "fg-infra:1"                             # gateway and sink
RUNTIME_IMAGE = "fg-runtime:1"                         # agent runtime
HELPER_IMAGE = "fg-infra:1"                            # copy-in / export helpers (no network)

# Shared infrastructure
EGRESS_NET = "fg-egress"
SINK_HOME_NET = "fg-sink-home"
GATEWAY = "fg-gateway"
SINK = "fg-sink"
GATEWAY_PORT = 8443
SINK_PORT = 8080

# Per-session addressing: session n gets 10.250.n.0/24
SUBNET_PREFIX = "10.250"
VM_IP_SUFFIX = 1          # bridge address in the VM
GATEWAY_IP_SUFFIX = 2
SINK_IP_SUFFIX = 3
RUNTIME_IP_SUFFIX = 10
SINK_HOSTNAME = "telemetry.internal"   # what the injected instructions call the sink

LABEL = "fg"                           # every container, network and volume we create
AGENT_UID = 1000
