"""Per-session egress policy, enforced by the VM on the session's bridge.

Each session has its own nftables table in the "bridge" family. Frames that
enter the bridge from the gateway's or sink's port are left alone; frames
from any other port (the runtime is the only other one) may reach the
gateway's API port and nothing else. Frames addressed to the VM itself are
dropped. Every drop is logged to the VM kernel log with the session ID,
where the detector reads it. See docs/decisions.md D1.
"""
import json
import subprocess

from . import config
from .registry import ip

PROFILES = ("secure", "vulnerable", "quarantine")
LOG_PREFIX = "fg-drop"


def bridge_name(sid: str) -> str:
    return f"br-fg-{sid}"          # Linux limits interface names to 15 characters


def table_name(sid: str) -> str:
    return f"fg_{sid}"


def bridge_ports(sid: str) -> list[str]:
    out = subprocess.run(["ip", "-j", "link", "show", "master", bridge_name(sid)],
                         check=True, capture_output=True, text=True).stdout
    return sorted(link["ifname"] for link in json.loads(out or "[]"))


def render(sid: str, n: int, infra_ports: list[str], profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile}")
    rt, gw, sink = ip(n, config.RUNTIME_IP_SUFFIX), ip(n, config.GATEWAY_IP_SUFFIX), ip(n, config.SINK_IP_SUFFIX)
    br = bridge_name(sid)
    ports = ", ".join(f'"{p}"' for p in infra_ports)

    allow = []
    if profile in ("secure", "vulnerable"):
        allow.append(f"ether type ip ip saddr {rt} ip daddr {gw} tcp dport {config.GATEWAY_PORT} accept")
    if profile == "vulnerable":
        # Deliberately vulnerable configuration: the sink is an allowed
        # destination. Used for the positive control and the failure demo.
        allow.append(f"ether type ip ip saddr {rt} ip daddr {sink} tcp dport {config.SINK_PORT} accept")
    allow_rules = "\n    ".join(allow)

    return f"""
table bridge {table_name(sid)} {{
  chain from_session {{
    type filter hook forward priority filter; policy accept;
    meta ibrname != "{br}" return
    iifname {{ {ports} }} accept
    ether type arp arp saddr ip {rt} accept
    {allow_rules}
    log prefix "{LOG_PREFIX} s={sid} p={profile} " level warn
    drop
  }}
  chain to_vm {{
    type filter hook input priority filter; policy accept;
    meta ibrname != "{br}" return
    ether type arp accept
    log prefix "{LOG_PREFIX}-vm s={sid} p={profile} " level warn
    drop
  }}
}}
"""


def apply(sid: str, n: int, infra_ports: list[str], profile: str) -> None:
    """Atomically replace the session's table, then check it is what we asked for."""
    script = f"table bridge {table_name(sid)}\ndelete table bridge {table_name(sid)}\n" + render(sid, n, infra_ports, profile)
    subprocess.run(["nft", "-f", "-"], input=script, check=True, text=True)
    verify(sid, profile)


def verify(sid: str, profile: str) -> None:
    out = subprocess.run(["nft", "list", "table", "bridge", table_name(sid)],
                         capture_output=True, text=True)
    if out.returncode != 0 or f"p={profile} " not in out.stdout or "drop" not in out.stdout:
        raise RuntimeError(f"egress policy for session {sid} is not loaded as {profile}")


def remove(sid: str) -> None:
    subprocess.run(["nft", "delete", "table", "bridge", table_name(sid)], capture_output=True)


def current_profile(sid: str) -> str | None:
    out = subprocess.run(["nft", "list", "table", "bridge", table_name(sid)], capture_output=True, text=True)
    for p in PROFILES:
        if f"p={p} " in out.stdout:
            return p
    return None
