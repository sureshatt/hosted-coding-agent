"""Delivery scanner: decides whether agent-written code may be published.

Runs as an unprivileged user with no network (see fg/delivery.py), on a work
directory prepared by the control plane:
  job.json      session id, tar sha256, canaries to look for
  export.tar    the agent's working tree (no .git), untrusted
  base/         the original repo files (trusted)
It writes verdict.json and changes.patch. It never runs git or any of the
agent's code; the export is treated purely as data.

Blocking checks: canary (raw or encoded), secret patterns, sensitive paths,
symlinks/devices/binaries, size limits.
Flags for the reviewer (not blocking): dependency changes, risky calls,
new URLs or hostnames.
"""
import difflib
import fnmatch
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fg.canary import find_canaries  # noqa: E402  (pure function, no I/O)

MAX_FILE = 200_000
MAX_DIFF = 500_000
SENSITIVE = [".github/*", ".gitlab-ci.yml", ".gitattributes", ".gitmodules", ".gitignore", ".git/*",
             "*Dockerfile*", ".pre-commit-config.yaml", "Makefile", ".env*", "*.pem", "*.key"]
SECRET_PATTERNS = {
    "private_key": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "aws_access_key": rb"\bAKIA[0-9A-Z]{16}\b",
    "anthropic_key": rb"\bsk-ant-[A-Za-z0-9_-]{20,}",
    "github_token": rb"\bgh[pousr]_[A-Za-z0-9]{30,}",
    "slack_token": rb"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "fg_session_token": rb"\bfgs_[A-Za-z0-9_-]{20,}",
}
DEP_FILES = ["requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "package.json", "*.lock", "Pipfile*"]
RISKY = rb"\b(eval|exec|subprocess|os\.system|socket|urllib|requests|http\.client|curl|wget|base64)\b"
URL_RE = rb"https?://[A-Za-z0-9.-]+"


def safe_extract(tar_path: Path, dest: Path) -> list[str]:
    """Unpack with the 'data' filter (no absolute paths, no '..', no devices,
    no permission bits beyond normal files) and refuse links outright."""
    problems = []
    with tarfile.open(tar_path) as tf:
        members = []
        for m in tf.getmembers():
            if m.issym() or m.islnk():
                problems.append(f"link not allowed: {m.name} -> {m.linkname}")
            elif m.isfile() or m.isdir():
                members.append(m)
            else:
                problems.append(f"special file not allowed: {m.name}")
        tf.extractall(dest, members=members, filter="data")
    return problems


def files(root: Path, ignore: list[str]) -> dict[str, bytes]:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_dir() or rel.startswith(".git/") or rel == ".git":
            continue
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(p.name, pat) or rel.startswith(pat.rstrip("/") + "/")
               for pat in ignore):
            continue
        out[rel] = p.read_bytes()
    return out


def ignore_patterns(base: Path) -> list[str]:
    """Ignore rules come from the trusted base repo, not the agent's copy."""
    gi = base / ".gitignore"
    pats = [l.strip() for l in gi.read_text().splitlines() if l.strip() and not l.startswith("#")] if gi.exists() else []
    return pats + ["__pycache__/", "*.pyc", ".pytest_cache/"]


def main(work: Path) -> int:
    job = json.loads((work / "job.json").read_text())
    tar = work / "export.tar"
    tar_sha = hashlib.sha256(tar.read_bytes()).hexdigest()
    blocks, flags = [], []
    if tar_sha != job["tar_sha256"]:
        blocks.append({"check": "integrity", "detail": "export changed after it was queued"})

    new_root = work / "new"
    new_root.mkdir()
    for p in safe_extract(tar, new_root):
        blocks.append({"check": "file_type", "detail": p})

    ignore = ignore_patterns(work / "base")
    before, after = files(work / "base", ignore), files(new_root, ignore)
    added = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(f for f in set(before) & set(after) if before[f] != after[f])
    changed = added + modified

    per_file = {}
    for f in sorted(added + modified + deleted):
        a = before.get(f, b"").decode("utf-8", "replace").splitlines(keepends=True)
        b = after.get(f, b"").decode("utf-8", "replace").splitlines(keepends=True)
        per_file[f] = list(difflib.unified_diff(a, b, f"a/{f}", f"b/{f}"))
    patch_text = "".join(line for f in sorted(per_file) for line in per_file[f])
    (work / "changes.patch").write_text(patch_text)

    if not changed and not deleted:
        blocks.append({"check": "empty", "detail": "no changes"})
    if len(patch_text) > MAX_DIFF:
        blocks.append({"check": "size", "detail": f"diff is {len(patch_text)} bytes"})
    for f in changed + deleted:
        if any(fnmatch.fnmatch(f, pat) for pat in SENSITIVE):
            blocks.append({"check": "sensitive_path", "file": f})
    for f in changed:
        data = after[f]
        if len(data) > MAX_FILE:
            blocks.append({"check": "size", "file": f, "detail": f"{len(data)} bytes"})
        if b"\0" in data:
            blocks.append({"check": "binary", "file": f})
        for hit in find_canaries(data + f.encode(), job["canaries"]):
            blocks.append({"check": "canary", "file": f, **hit})
        for name, pat in SECRET_PATTERNS.items():
            if re.search(pat, data):
                blocks.append({"check": "secret", "file": f, "pattern": name})
        if any(fnmatch.fnmatch(f.split("/")[-1], pat) for pat in DEP_FILES):
            flags.append({"check": "dependencies_changed", "file": f})
        added_lines = "".join(l[1:] for l in per_file[f]
                              if l.startswith("+") and not l.startswith("+++")).encode()
        for m in sorted(set(re.findall(RISKY, added_lines))):
            flags.append({"check": "risky_call", "file": f, "pattern": m.decode()})
        for m in sorted(set(re.findall(URL_RE, data)) - set(re.findall(URL_RE, before.get(f, b"")))):
            flags.append({"check": "new_url", "file": f, "url": m.decode()})

    verdict = {
        "session": job["session"], "tar_sha256": tar_sha,
        "decision": "block" if blocks else "pass",
        "blocking": blocks, "flags": flags,
        "added": added, "modified": modified, "deleted": deleted,
        "patch_sha256": hashlib.sha256(patch_text.encode()).hexdigest(),
    }
    (work / "verdict.json").write_text(json.dumps(verdict, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
