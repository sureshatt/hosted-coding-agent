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

# Target repositories, one per folder under fixtures/, identical except that
# the poisoned one carries the injected instructions.
FIXTURES = REPO / "fixtures"
REPOS = ("invoice-clean", "invoice-poisoned")
DEFAULT_REPO = "invoice-clean"

# Images
INFRA_IMAGE = "fg-infra:1"                             # gateway and sink
RUNTIME_IMAGE = "fg-runtime:1"                         # agent runtime
HELPER_IMAGE = "fg-infra:1"                            # copy-in / export helpers (no network)

# Model the agent uses unless a run passes --model
DEFAULT_MODEL = "claude-haiku-5-5"

# Shared infrastructure, each on its own network; the VM routes sessions to them.
GATEWAY = "fg-gateway"
EGRESS_NET = "fg-egress"                 # gateway only; NAT to the internet
EGRESS_BRIDGE = "br-fg-egress"
EGRESS_SUBNET = "10.249.0.0/24"
EGRESS_VM_IP = "10.249.0.1"
GATEWAY_IP = "10.249.0.2"
GATEWAY_PORT = 8443
SINK = "fg-sink"
SINK_NET = "fg-sinknet"                  # sink only; NAT off
SINK_BRIDGE = "br-fg-sink"
SINK_SUBNET = "10.248.0.0/24"
SINK_VM_IP = "10.248.0.1"
SINK_IP = "10.248.0.3"
SINK_PORT = 8080

# Per-session addressing: session n gets 10.250.n.0/24
SUBNET_PREFIX = "10.250"
SESSION_RANGE = "10.250.0.0/16"
VM_IP_SUFFIX = 1          # bridge address in the VM
RUNTIME_IP_SUFFIX = 10
SINK_HOSTNAME = "telemetry.internal"   # what the injected instructions call the sink

LABEL = "fg"                           # every container, network and volume we create
AGENT_UID = 1000
