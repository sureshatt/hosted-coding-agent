"""fgctl: control plane CLI. Runs as root inside the VM (see scripts/fgctl)."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

from . import config, evidence, netpolicy, registry, session


def cmd_setup(a):
    """Build images, create the local git remote, store the upstream
    credential (read from stdin, never from arguments) and start the gateway
    and sink."""
    for image, dockerfile in ((config.INFRA_IMAGE, "images/infra/Dockerfile"),
                              (config.RUNTIME_IMAGE, "images/runtime/Dockerfile")):
        print(f"building {image}")
        subprocess.run(["docker", "build", "-q", "-t", image, "-f", str(config.REPO / dockerfile), str(config.REPO)],
                       check=True, stdout=subprocess.DEVNULL)

    remote = config.GIT_REMOTE / "invoice.git"
    if not remote.exists():
        config.GIT_REMOTE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["cp", "-r", f"{config.REPO}/fixtures/invoice/.", tmp], check=True)
            g = ["git", "-C", tmp, "-c", "user.name=fg platform", "-c", "user.email=platform@fg.invalid"]
            subprocess.run(["git", "init", "-q", "-b", "main", tmp], check=True)
            subprocess.run([*g, "add", "-A"], check=True)
            subprocess.run([*g, "commit", "-q", "-m", "Initial fixture"], check=True)
            subprocess.run(["git", "clone", "-q", "--bare", tmp, str(remote)], check=True)
        print(f"created local git remote {remote}")

    if a.credential_from_stdin:
        cred = sys.stdin.read().strip()
        kind = "FG_UPSTREAM_OAUTH_TOKEN" if cred.startswith("sk-ant-oat") else "FG_UPSTREAM_API_KEY"
        config.SECRETS.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = config.SECRETS / "upstream.env"
        path.write_text(f"{kind}={cred}\n")
        os.chmod(path, 0o600)
        print(f"stored upstream credential ({kind})")
        subprocess.run(["docker", "rm", "-f", config.GATEWAY], capture_output=True)

    upstream = "anthropic" if (config.SECRETS / "upstream.env").exists() and \
        (config.SECRETS / "upstream.env").read_text().strip() else "mock"
    if a.mock:
        upstream = "mock"
    current = subprocess.run(["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", config.GATEWAY],
                             capture_output=True, text=True).stdout
    if current and f"FG_UPSTREAM={upstream}" not in current:
        subprocess.run(["docker", "rm", "-f", config.GATEWAY], capture_output=True)
    session.start_infra(upstream)
    print(f"gateway running (upstream: {upstream}); sink running")


def cmd_create(a):
    sid = session.create(a.user, a.profile)
    print(sid)


def cmd_run(a):
    session.run(a.session, a.mode, a.arg, a.model)
    print(f"session {a.session} running")


def cmd_start(a):
    """create + run in one step."""
    sid = session.create(a.user, a.profile)
    session.run(sid, "agent", a.task, a.model)
    print(sid)


def _summarise(line: str) -> str | None:
    """One readable line per agent event (stream-json from Claude Code)."""
    try:
        ev = json.loads(line)
    except ValueError:
        return line
    t = ev.get("type")
    if t == "assistant":
        parts = []
        for c in ev.get("message", {}).get("content", []):
            if c.get("type") == "text" and c["text"].strip():
                parts.append("say: " + c["text"].strip().replace("\n", " ")[:160])
            elif c.get("type") == "tool_use":
                inp = json.dumps(c.get("input", {}))[:160]
                parts.append(f"tool: {c['name']} {inp}")
        return "\n".join(parts) or None
    if t == "result":
        return f"done: {ev.get('subtype')} turns={ev.get('num_turns')} cost=${ev.get('total_cost_usd', 0):.2f}"
    if t == "system" and ev.get("subtype") == "init":
        return f"start: model={ev.get('model')}"
    return None


def cmd_logs(a):
    args = ["docker", "logs"] + (["-f"] if a.follow else []) + [session.runtime_name(a.session)]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        out = line.rstrip() if a.raw else _summarise(line.strip())
        if out:
            print(out, flush=True)


def cmd_wait(a):
    code = session.wait(a.session, a.timeout)
    print("timeout" if code is None else f"exit {code}")


def cmd_status(a):
    rows = registry.all_sessions()
    if not rows:
        print("no sessions")
    for s in rows:
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", session.runtime_name(s["id"])],
                               capture_output=True, text=True).stdout.strip() or "-"
        print(f"{s['id']}  user={s['user']}  state={s['state']}  runtime={state}  "
              f"policy={netpolicy.current_profile(s['id'])}  net=10.250.{s['subnet_n']}.0/24")


def cmd_stop(a):
    session.stop(a.session)
    print(f"stopped {a.session}")


def cmd_destroy(a):
    session.destroy(a.session)
    print(f"destroyed {a.session}")


def cmd_contain(a):
    print(json.dumps(session.contain(a.session, a.reason, by=f"manual:{a.user}"), indent=2))


def cmd_evidence(a):
    ok = True
    for s in evidence.streams():
        good, msg = evidence.verify(s)
        ok &= good
        print(("OK   " if good else "FAIL ") + msg)
    sys.exit(0 if ok else 1)


def cmd_detector(a):
    from . import detector
    detector.main()


def cmd_deliver(a):
    from . import delivery
    print(json.dumps(delivery.deliver(a.session), indent=2))


def cmd_test(a):
    from . import harness
    sys.exit(harness.main(a))


def main():
    p = argparse.ArgumentParser(prog="fgctl")
    p.add_argument("--user", default=os.environ.get("FG_USER") or os.environ.get("SUDO_USER") or "unknown",
                   help="initiating user (asserted by the caller in this prototype)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup"); s.set_defaults(f=cmd_setup)
    s.add_argument("--credential-from-stdin", action="store_true")
    s.add_argument("--mock", action="store_true", help="use the mock model even if a credential is stored")

    s = sub.add_parser("create"); s.set_defaults(f=cmd_create)
    s.add_argument("--profile", default="secure", choices=["secure", "vulnerable"])

    s = sub.add_parser("run"); s.set_defaults(f=cmd_run)
    s.add_argument("session"); s.add_argument("mode", choices=["agent", "shell"]); s.add_argument("arg")
    s.add_argument("--model")

    s = sub.add_parser("start", help="create a session and run the agent on a task"); s.set_defaults(f=cmd_start)
    s.add_argument("task"); s.add_argument("--profile", default="secure", choices=["secure", "vulnerable"])
    s.add_argument("--model")

    s = sub.add_parser("logs"); s.set_defaults(f=cmd_logs)
    s.add_argument("session"); s.add_argument("-f", "--follow", action="store_true"); s.add_argument("--raw", action="store_true")

    s = sub.add_parser("wait"); s.set_defaults(f=cmd_wait)
    s.add_argument("session"); s.add_argument("--timeout", type=int, default=900)

    sub.add_parser("status").set_defaults(f=cmd_status)
    for name, f in (("stop", cmd_stop), ("destroy", cmd_destroy), ("deliver", cmd_deliver)):
        s = sub.add_parser(name); s.set_defaults(f=f); s.add_argument("session")
    s = sub.add_parser("contain"); s.set_defaults(f=cmd_contain)
    s.add_argument("session"); s.add_argument("--reason", default="manual containment")

    sub.add_parser("evidence-verify").set_defaults(f=cmd_evidence)
    sub.add_parser("detector").set_defaults(f=cmd_detector)
    s = sub.add_parser("test", help="run the security test harness"); s.set_defaults(f=cmd_test)
    s.add_argument("--agent-runs", type=int, default=1, help="prompt-injection runs (need a credential)")
    s.add_argument("--skip-agent", action="store_true", help="only the deterministic tests")
    s.add_argument("--model")

    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("fgctl must run as root in the VM; use scripts/fgctl from the host")
    a.f(a)


if __name__ == "__main__":
    main()
