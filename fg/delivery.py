"""Delivery: get agent-written code out of a session and onto a branch.

  export     a helper container with no network reads the workspace
             read-only and tars the working tree, excluding .git
  scan       services/scanner.py, as an unprivileged user in a network
             namespace with no interfaces, writes a verdict
  publish    only if the verdict passes and still matches the exported
             bytes: apply the files in a clean clone we own and push a
             branch to the git remote; never merge

The agent's .git is never used: its config could make git run commands.
The control plane only runs git in repositories it created.
In production the scanner would be a separate, horizontally scaled worker
behind a queue, and the publisher a separate service holding a GitHub App
token scoped to one repository.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from . import config, evidence, registry
from .session import docker, volume_name

NOBODY = 65534
LOG = config.LOGS / "delivery" / "delivery.jsonl"


def _log(event: str, **fields):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps({"ts": time.time(), "source": "delivery", "event": event, **fields}, sort_keys=True) + "\n")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def export(sid: str, work: Path) -> Path:
    tar = work / "export.tar"
    with tar.open("wb") as f:
        subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL",
                        "--cap-add", "DAC_READ_SEARCH", "-v", f"{volume_name(sid)}:/workspace:ro",
                        config.HELPER_IMAGE, "tar", "-C", "/workspace", "--exclude=./.git", "-cf", "-", "."],
                       stdout=f, check=True)
    return tar


def scan(work: Path) -> dict:
    """Run the scanner as nobody, with no network, on files it owns."""
    subprocess.run(["chown", "-R", f"{NOBODY}:{NOBODY}", str(work)], check=True)
    r = subprocess.run(["unshare", "--net", "--",
                        "setpriv", f"--reuid={NOBODY}", f"--regid={NOBODY}", "--clear-groups", "--no-new-privs",
                        "python3", "-I", "-B", str(config.REPO / "services" / "scanner.py"), str(work)],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return {"decision": "block", "blocking": [{"check": "scanner_error", "detail": r.stderr[-500:]}], "flags": []}
    return json.loads((work / "verdict.json").read_text())


def publish(sid: str, repo: str, tar: Path, verdict: dict, user: str) -> str:
    branch = f"agent/{sid}"
    with tempfile.TemporaryDirectory() as tmp:
        clone = Path(tmp) / "clone"
        extracted = Path(tmp) / "x"
        g = ["git", "-C", str(clone), "-c", "user.name=fg platform", "-c", "user.email=platform@fg.invalid",
             "-c", "core.hooksPath=/dev/null"]
        subprocess.run(["git", "clone", "-q", str(config.GIT_REMOTE / f"{repo}.git"), str(clone)], check=True)
        extracted.mkdir()
        with tarfile.open(tar) as tf:
            tf.extractall(extracted, members=[m for m in tf.getmembers() if m.isfile() or m.isdir()], filter="data")
        for f in verdict["deleted"]:
            (clone / f).unlink(missing_ok=True)
        for f in verdict["added"] + verdict["modified"]:
            (clone / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(extracted / f, clone / f)
        subprocess.run([*g, "checkout", "-q", "-b", branch], check=True)
        subprocess.run([*g, "add", "-A"], check=True)
        staged = subprocess.run([*g, "diff", "--cached", "--name-only"], capture_output=True, text=True,
                                check=True).stdout.split()
        expected = sorted(verdict["added"] + verdict["modified"] + verdict["deleted"])
        if sorted(staged) != expected:
            raise RuntimeError(f"staged files {staged} differ from the scanned change set {expected}")
        msg = (f"Agent change from session {sid}\n\nInitiated by: {user}\nScanned export sha256: {verdict['tar_sha256']}\n"
               f"Reviewer flags: {json.dumps(verdict['flags'])}\n")
        subprocess.run([*g, "commit", "-q", "-m", msg], check=True)
        subprocess.run([*g, "push", "-q", "origin", branch], check=True)
        return subprocess.run([*g, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


def deliver(sid: str) -> dict:
    s = registry.get(sid)
    if s is None:
        raise RuntimeError(f"unknown session {sid}")
    repo = s["repo"]
    work = Path(tempfile.mkdtemp(prefix=f"fg-deliver-{sid}-"))
    try:
        tar = export(sid, work)
        base = work / "base"
        subprocess.run(["git", "clone", "-q", str(config.GIT_REMOTE / f"{repo}.git"), str(base)], check=True)
        shutil.rmtree(base / ".git")
        job = {"session": sid, "tar_sha256": _sha(tar),
               "canaries": {r["id"]: r["canary"] for r in registry.all_sessions()}}
        (work / "job.json").write_text(json.dumps(job))
        verdict = scan(work)
        patch = (work / "changes.patch").read_text() if (work / "changes.patch").exists() else ""

        result = {"session": sid, "user": s["user"], "decision": verdict["decision"],
                  "blocking": verdict.get("blocking", []), "flags": verdict.get("flags", []),
                  "files": sorted(verdict.get("added", []) + verdict.get("modified", []) + verdict.get("deleted", []))}
        if verdict["decision"] == "pass" and verdict.get("tar_sha256") == _sha(tar):
            result["branch"] = f"agent/{sid}"
            result["commit"] = publish(sid, repo, tar, verdict, s["user"])
            _log("delivery_published", session=sid, branch=result["branch"], commit=result["commit"],
                 flags=result["flags"])
        else:
            _log("delivery_blocked", session=sid, findings=result["blocking"])
        evidence.append("delivery", f"delivery_{result['decision']}", {**result, "patch": patch[:20000]})
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
