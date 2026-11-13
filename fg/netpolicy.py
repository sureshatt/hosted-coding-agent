"""Egress policy, enforced by the VM. See docs/decisions.md D1 and D3.

Sessions. Each session's runtime is the only thing on its bridge. The
gateway and sink live on their own networks, and the VM routes to them. A
per-session nftables table (bridge family) sees every frame the runtime
sends, before the VM or Docker's own rules see it:
  - to the gateway's API port: passed on to routing
  - to the sink: passed on only in the deliberately vulnerable profile
  - anything else (internet, DNS, the VM, other sessions): logged, dropped
Routing between Docker networks is then refused by Docker twice: its
direct-routing protection (raw PREROUTING drops packets for a container's
address arriving from another bridge) and its forward drop. We add a
matching ACCEPT to each, for exactly that flow (runtime -> gateway:8443 and
the replies), tagged with the session id and removed on quarantine or
destroy. Independent layers: our bridge table, then Docker's own rules.

Gateway. Its own table on the egress bridge: DNS to the VM's resolver and
HTTPS to public addresses only, replies to sessions; nothing to private
ranges, the VM or the Mac.
"""
import ipaddress
import subprocess

from . import config
from .registry import ip

PROFILES = ("secure", "vulnerable", "quarantine")
LOG_PREFIX = "fg-drop"


def bridge_name(sid: str) -> str:
    return f"br-fg-{sid}"          # Linux limits interface names to 15 characters


def table_name(sid: str) -> str:
    return f"fg_{sid}"


def _nft(script: str) -> None:
    subprocess.run(["nft", "-f", "-"], input=script, check=True, text=True)


# --- per-session ------------------------------------------------------------

def render(sid: str, n: int, profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile}")
    rt = ip(n, config.RUNTIME_IP_SUFFIX)
    allow = []
    if profile in ("secure", "vulnerable"):
        allow.append(f"ip daddr {config.GATEWAY_IP} tcp dport {config.GATEWAY_PORT} accept")
    if profile == "vulnerable":
        # Deliberately vulnerable configuration: the sink is an allowed
        # destination. Used for the positive control and the failure demo.
        allow.append(f"ip daddr {config.SINK_IP} tcp dport {config.SINK_PORT} accept")
    allow_rules = "\n    ".join(allow)
    br = bridge_name(sid)
    return f"""
table bridge {table_name(sid)} {{
  chain to_vm {{
    # Every frame the runtime sends. Prerouting at priority filter (-200)
    # runs before br_netfilter (0), which runs Docker's iptables raw rules;
    # hooked later, Docker would drop some destinations before we log them.
    type filter hook prerouting priority filter; policy accept;
    meta ibrname != "{br}" return
    ether type arp arp saddr ip {rt} accept
    ether type ip ip saddr != {rt} log prefix "{LOG_PREFIX}-spoof s={sid} p={profile} " level warn drop
    ether type ip jump allowed
    log prefix "{LOG_PREFIX}-vm s={sid} p={profile} " level warn
    drop
  }}
  chain allowed {{
    {allow_rules}
    log prefix "{LOG_PREFIX} s={sid} p={profile} " level warn
    drop
  }}
  chain bridged {{
    # Frames between ports of this bridge. The runtime should be alone on it.
    type filter hook forward priority filter; policy accept;
    meta ibrname != "{br}" return
    log prefix "{LOG_PREFIX}-bridged s={sid} p={profile} " level warn
    drop
  }}
}}
"""


def _routing_rules(sid: str, n: int, profile: str) -> list[tuple[str, list[str]]]:
    """(iptables table, rule) pairs that let Docker route the flows this
    profile allows: a raw ACCEPT past the direct-routing protection, and a
    DOCKER-USER ACCEPT past the forward drop, in both directions."""
    rt, br, tag = ip(n, config.RUNTIME_IP_SUFFIX), bridge_name(sid), ["-m", "comment", "--comment", f"fg:{sid}"]
    flows = []
    if profile in ("secure", "vulnerable"):
        flows.append((config.EGRESS_BRIDGE, config.GATEWAY_IP, config.GATEWAY_PORT))
    if profile == "vulnerable":
        flows.append((config.SINK_BRIDGE, config.SINK_IP, config.SINK_PORT))
    rules = []
    for out_br, dst, port in flows:
        out = ["-i", br, "-o", out_br, "-s", rt, "-d", dst, "-p", "tcp", "--dport", str(port)]
        back = ["-i", out_br, "-o", br, "-s", dst, "-d", rt, "-p", "tcp", "--sport", str(port)]
        rules += [
            ("raw", ["PREROUTING", *[a for a in out if a not in ("-o", out_br)], *tag, "-j", "ACCEPT"]),
            ("raw", ["PREROUTING", *[a for a in back if a not in ("-o", br)], *tag, "-j", "ACCEPT"]),
            ("filter", ["DOCKER-USER", *out, *tag, "-j", "ACCEPT"]),
            ("filter", ["DOCKER-USER", *back, "-m", "conntrack", "--ctstate", "ESTABLISHED", *tag, "-j", "ACCEPT"]),
        ]
    return rules


def _tagged(sid: str) -> list[tuple[str, str]]:
    found = []
    for table, chain in (("raw", "PREROUTING"), ("filter", "DOCKER-USER")):
        out = subprocess.run(["iptables", "-w", "-t", table, "-S", chain], capture_output=True, text=True).stdout
        found += [(table, line) for line in out.splitlines() if f"fg:{sid}" in line.replace('"', "").split()]
    return found


def _remove_routing_rules(sid: str) -> None:
    for table, line in _tagged(sid):
        args = line.split()
        args[0] = "-D"
        subprocess.run(["iptables", "-w", "-t", table, *[a.strip('"') for a in args]], check=True)


def apply(sid: str, n: int, profile: str) -> None:
    """Replace the session's bridge table atomically, then its routing
    rules, then check both are what we asked for."""
    _nft(f"table bridge {table_name(sid)}\ndelete table bridge {table_name(sid)}\n" + render(sid, n, profile))
    _remove_routing_rules(sid)
    for table, (chain, *rule) in _routing_rules(sid, n, profile):
        subprocess.run(["iptables", "-w", "-t", table, "-I", chain, *rule], check=True)
    verify(sid, n, profile)


def verify(sid: str, n: int, profile: str) -> None:
    out = subprocess.run(["nft", "list", "table", "bridge", table_name(sid)], capture_output=True, text=True)
    if out.returncode != 0 or f"p={profile} " not in out.stdout or "drop" not in out.stdout:
        raise RuntimeError(f"egress policy for session {sid} is not loaded as {profile}")
    if len(_tagged(sid)) != len(_routing_rules(sid, n, profile)):
        raise RuntimeError(f"routing rules for session {sid} do not match profile {profile}")


def remove(sid: str) -> None:
    subprocess.run(["nft", "delete", "table", "bridge", table_name(sid)], capture_output=True)
    _remove_routing_rules(sid)


def current_profile(sid: str) -> str | None:
    out = subprocess.run(["nft", "list", "table", "bridge", table_name(sid)], capture_output=True, text=True)
    for p in PROFILES:
        if f"p={p} " in out.stdout:
            return p
    return None


# --- gateway ------------------------------------------------------------------

PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8"]


def apply_gateway_egress(dns_server: str) -> None:
    """The gateway may resolve names through the VM's resolver and open
    HTTPS connections to public addresses; it may answer sessions. Nothing
    else: no private ranges, no VM services, no Mac."""
    ipaddress.ip_address(dns_server)
    private = ", ".join(PRIVATE)
    _nft(f"""
table bridge fg_gateway
delete table bridge fg_gateway
table bridge fg_gateway {{
  chain out {{
    type filter hook prerouting priority filter; policy accept;
    meta ibrname != "{config.EGRESS_BRIDGE}" return
    ether type arp accept
    ip saddr != {config.GATEWAY_IP} log prefix "{LOG_PREFIX}-gw-spoof " level warn drop
    ip daddr {dns_server} meta l4proto {{ tcp, udp }} th dport 53 accept
    ip daddr {config.SESSION_RANGE} tcp sport {config.GATEWAY_PORT} accept
    ip daddr {config.EGRESS_VM_IP} tcp sport {config.GATEWAY_PORT} accept
    ip daddr {{ {private} }} log prefix "{LOG_PREFIX}-gw " level warn drop
    tcp dport 443 accept
    log prefix "{LOG_PREFIX}-gw " level warn
    drop
  }}
}}
""")
