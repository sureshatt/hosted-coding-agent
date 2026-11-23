"""Session lifecycle: create, run, stop, destroy, contain.

Everything here runs as root in the VM and talks to Docker and nftables
directly. Nothing here reads content produced inside a session except
through the helpers in delivery.py, which treat it as untrusted.
"""
import hashlib
import json
import os
import secrets
import subprocess
import time
import urllib.request

from . import config, evidence, netpolicy, registry
from .registry import ip


def sh(*args, check=True, capture=True, input=None) -> str:
    r = subprocess.run(list(args), check=False, capture_output=capture, text=True, input=input)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])}... failed: {(r.stderr or '').strip()}")
    return (r.stdout or "").strip()


def docker(*args, **kw) -> str:
    return sh("docker", *args, **kw)


def net_name(sid): return f"fg-s-{sid}"
def runtime_name(sid): return f"fg-rt-{sid}"
def volume_name(sid): return f"fg-ws-{sid}"
def session_dir(sid): return config.STATE / "sessions" / sid


# --- shared infrastructure ---------------------------------------------------

HARDENING = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--pids-limit", "256", "--memory", "512m"]


def running(name: str) -> bool:
    return docker("ps", "-q", "--filter", f"name=^{name}$") != ""


def start_infra(upstream: str) -> None:
    """Egress network, model gateway and sink. Idempotent."""
    for d in (config.GATEWAY_STATE, config.LOGS / "gateway", config.LOGS / "sink", config.SECRETS):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(config.SECRETS, 0o700)
    os.chmod(config.GATEWAY_STATE, 0o755)
    for d in ("gateway", "sink"):
        os.chown(config.LOGS / d, 10001, 10001)
    tokens_file = config.GATEWAY_STATE / "tokens.json"
    if not tokens_file.exists():
        _write_tokens({})
    secret_env = config.SECRETS / "upstream.env"
    if not secret_env.exists():
        secret_env.write_text("")
        os.chmod(secret_env, 0o600)

    for name, bridge, subnet, vm_ip, nat in (
            (config.EGRESS_NET, config.EGRESS_BRIDGE, config.EGRESS_SUBNET, config.EGRESS_VM_IP, "true"),
            (config.SINK_NET, config.SINK_BRIDGE, config.SINK_SUBNET, config.SINK_VM_IP, "false")):
        if not docker("network", "ls", "-q", "--filter", f"name=^{name}$"):
            docker("network", "create", "--label", config.LABEL, "--subnet", subnet, "--gateway", vm_ip,
                   "-o", f"com.docker.network.bridge.name={bridge}",
                   "-o", f"com.docker.network.bridge.enable_ip_masquerade={nat}", name)

    # The gateway needs DNS for api.anthropic.com. Docker's embedded
    # resolver does not work under gVisor, so point it at the VM's upstream
    # resolver, which its egress policy allows (and nothing else private).
    dns = _vm_resolver()
    resolv = config.GATEWAY_STATE.parent / "gateway-resolv.conf"
    resolv.write_text(f"nameserver {dns}\n")
    os.chmod(resolv, 0o644)
    netpolicy.apply_gateway_egress(dns)

    # Both run in gVisor, each on its own network; nothing is attached to
    # a running container later (gVisor would not see it: docs/decisions.md D3).
    if not running(config.GATEWAY):
        docker("rm", "-f", config.GATEWAY, check=False)
        docker("run", "-d", "--name", config.GATEWAY, "--label", config.LABEL, "--restart", "unless-stopped",
               "--runtime", "runsc", "--network", config.EGRESS_NET, "--ip", config.GATEWAY_IP, *HARDENING,
               "-v", f"{resolv}:/etc/resolv.conf:ro",
               "--env-file", str(secret_env), "-e", f"FG_UPSTREAM={upstream}",
               "-v", f"{config.GATEWAY_STATE}:/etc/fg:ro",
               "-v", f"{config.LOGS / 'gateway'}:/var/log/fg",
               config.INFRA_IMAGE, "python3", "-B", "/srv/gateway.py")
    if not running(config.SINK):
        docker("rm", "-f", config.SINK, check=False)
        docker("run", "-d", "--name", config.SINK, "--label", config.LABEL, "--restart", "unless-stopped",
               "--runtime", "runsc", "--network", config.SINK_NET, "--ip", config.SINK_IP, *HARDENING,
               "-v", f"{config.LOGS / 'sink'}:/var/log/fg",
               config.INFRA_IMAGE, "python3", "-B", "/srv/sink.py")


def _vm_resolver() -> str:
    for line in open("/run/systemd/resolve/resolv.conf"):
        if line.startswith("nameserver"):
            return line.split()[1]
    raise RuntimeError("no upstream DNS server found in the VM")


# --- gateway tokens ----------------------------------------------------------

def _read_tokens() -> dict:
    return json.loads((config.GATEWAY_STATE / "tokens.json").read_text())


def _write_tokens(data: dict) -> None:
    # Write-then-rename inside the mounted directory, so the gateway never
    # reads a partial file and sees the change on its next request.
    tmp = config.GATEWAY_STATE / ".tokens.json.tmp"
    tmp.write_text(json.dumps(data, indent=1))
    os.chmod(tmp, 0o644)
    os.replace(tmp, config.GATEWAY_STATE / "tokens.json")


def revoke_token(sid: str) -> None:
    data = _read_tokens()
    data = {h: v for h, v in data.items() if v["session"] != sid}
    _write_tokens(data)


# --- lifecycle ---------------------------------------------------------------

def create(user: str, profile: str = "secure", repo: str = config.DEFAULT_REPO) -> str:
    if profile not in ("secure", "vulnerable"):
        raise ValueError("profile must be secure or vulnerable")
    if not running(config.GATEWAY) or not running(config.SINK):
        raise RuntimeError("infrastructure is not running; run setup first")
    sid = secrets.token_hex(4)
    canary = "FGCANARY-" + secrets.token_hex(16)
    token = "fgs_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    with registry.db() as conn:
        n = registry.allocate_subnet(conn)
        registry.add(conn, id=sid, user=user, profile=profile, subnet_n=n, canary=canary,
                     token_hash=token_hash, task=None, repo=repo, state="creating")
    try:
        # 1. Session network: a normal bridge with NAT off, so attempts to
        #    leave reach the VM (and are logged) but nothing is translated out.
        docker("network", "create", "--label", config.LABEL, "--label", f"fg.session={sid}",
               "--subnet", f"{config.SUBNET_PREFIX}.{n}.0/24", "--gateway", ip(n, config.VM_IP_SUFFIX),
               "-o", "com.docker.network.bridge.enable_ip_masquerade=false",
               "-o", f"com.docker.network.bridge.name={netpolicy.bridge_name(sid)}",
               net_name(sid))

        # 2. Egress policy, before the runtime exists.
        netpolicy.apply(sid, n, profile)
        (session_dir(sid)).mkdir(parents=True, exist_ok=True)

        # 3. Session token, bound to the runtime's address.
        data = _read_tokens()
        data[token_hash] = {"session": sid, "runtime_ip": ip(n, config.RUNTIME_IP_SUFFIX), "canary": canary}
        _write_tokens(data)
        (session_dir(sid) / "token").write_text(token)
        os.chmod(session_dir(sid) / "token", 0o600)

        # 4. Workspace: a clone of the repo from the local git remote, plus a
        #    .env holding the canary (a synthetic secret, unique per session).
        docker("volume", "create", "--label", config.LABEL, "--label", f"fg.session={sid}", volume_name(sid))
        docker("run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL",
               "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
               "-v", f"{volume_name(sid)}:/workspace", "-v", f"{config.GIT_REMOTE}:/remote:ro",
               config.HELPER_IMAGE, "sh", "-c",
               f"git clone -q /remote/{repo}.git /workspace"
               f" && printf 'PAYMENTS_API_KEY=%s\\nPAYMENTS_ENV=sandbox\\n' '{canary}' > /workspace/.env"
               f" && chown -R {config.AGENT_UID}:{config.AGENT_UID} /workspace")

        (session_dir(sid) / "resolv.conf").write_text(f"nameserver {ip(n, config.VM_IP_SUFFIX)}\n")
        os.chmod(session_dir(sid) / "resolv.conf", 0o644)
    except Exception:
        destroy(sid, quiet=True)
        raise

    registry.set_state(sid, "ready")
    evidence.append("sessions", "session_created", {
        "session": sid, "user": user, "profile": profile, "repo": repo,
        "network": net_name(sid), "bridge": netpolicy.bridge_name(sid),
        "runtime_ip": ip(n, config.RUNTIME_IP_SUFFIX), "token_sha256": token_hash,
        "canary_sha256": hashlib.sha256(canary.encode()).hexdigest()})
    return sid


def run(sid: str, mode: str, arg: str, model: str | None = None) -> None:
    s = registry.get(sid)
    if s is None or s["state"] != "ready":
        raise RuntimeError(f"session {sid} is not ready")
    n = s["subnet_n"]
    gw = config.GATEWAY_IP
    token = (session_dir(sid) / "token").read_text()
    env = {
        "ANTHROPIC_BASE_URL": f"http://{gw}:{config.GATEWAY_PORT}",
        "ANTHROPIC_AUTH_TOKEN": token,
        # Telemetry, error reporting and update checks would be blocked anyway;
        # turning them off keeps them from looking like exfiltration attempts.
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "FG_SESSION": sid,
        "FG_MODEL": model or config.DEFAULT_MODEL,
    }
    env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
    docker("run", "-d", "--name", runtime_name(sid), "--label", config.LABEL, "--label", f"fg.session={sid}",
           "--runtime", "runsc",
           "--network", net_name(sid), "--ip", ip(n, config.RUNTIME_IP_SUFFIX),
           "-v", f"{session_dir(sid) / 'resolv.conf'}:/etc/resolv.conf:ro",
           "--add-host", f"{config.SINK_HOSTNAME}:{config.SINK_IP}",
           "-v", f"{volume_name(sid)}:/workspace",
           "--read-only", "--tmpfs", "/tmp", "--tmpfs", f"/home/agent:uid={config.AGENT_UID},gid={config.AGENT_UID}",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", "512", "--memory", "2g", "--cpus", "2",
           *env_args, config.RUNTIME_IMAGE, mode, arg)
    with registry.db() as conn:
        conn.execute("UPDATE sessions SET task=?, state='running', updated=? WHERE id=?", (arg, time.time(), sid))
    evidence.append("sessions", "session_started", {"session": sid, "user": s["user"], "mode": mode, "task": arg})


def wait(sid: str, timeout: int) -> int | None:
    try:
        out = subprocess.run(["docker", "wait", runtime_name(sid)], capture_output=True, text=True, timeout=timeout)
        code = int(out.stdout.strip()) if out.stdout.strip() else None
    except subprocess.TimeoutExpired:
        return None
    if registry.get(sid) and registry.get(sid)["state"] == "running":
        registry.set_state(sid, "finished")
    return code


def stop(sid: str) -> None:
    docker("stop", "-t", "5", runtime_name(sid), check=False)
    registry.set_state(sid, "stopped")
    evidence.append("sessions", "session_stopped", {"session": sid})


def destroy(sid: str, quiet: bool = False) -> None:
    """Remove everything the session had; access ends with it."""
    revoke_token(sid)
    docker("rm", "-f", runtime_name(sid), check=False)
    netpolicy.remove(sid)
    docker("network", "rm", net_name(sid), check=False)
    docker("volume", "rm", "-f", volume_name(sid), check=False)
    sh("rm", "-rf", str(session_dir(sid)), check=False)
    registry.remove(sid)
    if not quiet:
        evidence.append("sessions", "session_destroyed", {"session": sid})


# --- containment --------------------------------------------------------------

def _token_rejected_as_revoked(sid: str) -> bool:
    """Present the session's token to the gateway from the VM (over the
    egress network; session bridges drop traffic to the VM). Any probe from
    here is rejected; the gateway's log says whether it was because the
    token is revoked, which is what we need to confirm."""
    token = (session_dir(sid) / "token").read_text()
    gw = config.GATEWAY_IP
    t = time.time()
    req = urllib.request.Request(f"http://{gw}:{config.GATEWAY_PORT}/v1/messages", data=b"{}", method="POST",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        urllib.request.urlopen(req, timeout=5)
        return False
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return False
    time.sleep(0.2)
    for line in reversed((config.LOGS / "gateway" / "gateway.jsonl").read_text().splitlines()[-50:]):
        ev = json.loads(line)
        if ev["ts"] >= t and ev["event"] == "auth_failed":
            return ev.get("reason") == "unknown or revoked token"
    return False


def contain(sid: str, reason: str, by: str) -> dict:
    """Cut the network, revoke access, preserve evidence, then remove the
    runtime; verify each step from outside the session."""
    s = registry.get(sid)
    if s is None:
        raise RuntimeError(f"unknown session {sid}")
    n = s["subnet_n"]
    steps = []
    t0 = time.time()

    def step(name, fn):
        # Every step runs even if an earlier one failed; failures are recorded.
        try:
            verified, detail = fn()
        except Exception as e:  # noqa: BLE001 - containment must not stop half way
            verified, detail = False, {"error": str(e)}
        steps.append({"step": name, "verified": verified, **detail})

    def quarantine():
        # Nothing from the runtime, not even to the gateway.
        netpolicy.apply(sid, n, "quarantine")
        return netpolicy.current_profile(sid) == "quarantine", {}

    def revoke():
        revoke_token(sid)
        listed = any(v["session"] == sid for v in _read_tokens().values())
        rejected = _token_rejected_as_revoked(sid)
        return (not listed) and rejected, {"gateway_rejects_as_revoked": rejected}

    snap = config.SNAPSHOTS / f"{sid}-{int(t0)}"

    def preserve():
        snap.mkdir(parents=True, exist_ok=True)
        (snap / "runtime-inspect.json").write_text(docker("inspect", runtime_name(sid), check=False))
        (snap / "runtime-output.log").write_text(docker("logs", runtime_name(sid), check=False))
        (snap / "nft-table.txt").write_text(sh("nft", "list", "table", "bridge", netpolicy.table_name(sid), check=False))
        with open(snap / "workspace.tar", "wb") as f:
            # A helper with no network reads the workspace read-only; tar
            # never runs inside the untrusted runtime.
            subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL",
                            "--cap-add", "DAC_READ_SEARCH",
                            "-v", f"{volume_name(sid)}:/workspace:ro", config.HELPER_IMAGE,
                            "tar", "-C", "/workspace", "-cf", "-", "."], stdout=f, check=True)
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(snap.iterdir())}
        return len(hashes) == 4, {"path": str(snap), "sha256": hashes}

    def remove_runtime():
        docker("rm", "-f", runtime_name(sid), check=False)
        return not running(runtime_name(sid)), {}

    # Network first (stops further damage), then credentials, then evidence
    # (before anything is destroyed), then the runtime itself.
    step("network_quarantined", quarantine)
    step("token_revoked", revoke)
    step("evidence_preserved", preserve)
    step("runtime_removed", remove_runtime)

    ok = all(st["verified"] for st in steps)
    registry.set_state(sid, "contained")
    result = {"session": sid, "user": s["user"], "reason": reason, "by": by,
              "seconds": round(time.time() - t0, 2), "all_verified": ok, "steps": steps}
    evidence.append("containment", "session_contained", result)
    return result
