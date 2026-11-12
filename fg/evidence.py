"""Append-only, hash-chained evidence logs.

Each line is a JSON record carrying the SHA-256 of the previous line, so any
edit, deletion or reordering breaks the chain at that point. This protects
against tampering by anything that can append but not rewrite history
consistently; it does not protect against root on the VM, which could rewrite
the whole chain. Production would ship each record off the machine (for
example to object storage with a retention lock) as it is written.
"""
import fcntl
import hashlib
import json
import time
from pathlib import Path

from . import config

GENESIS = "0" * 64


def _path(stream: str) -> Path:
    return config.EVIDENCE / f"{stream}.jsonl"


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65536))
        last = f.read().splitlines()[-1]
    return json.loads(last)["hash"]


def append(stream: str, kind: str, data: dict) -> dict:
    config.EVIDENCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _path(stream)
    with path.open("a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        prev = _last_hash(path)
        record = {"ts": time.time(), "stream": stream, "kind": kind, "data": data, "prev": prev}
        body = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["hash"] = hashlib.sha256(body.encode()).hexdigest()
        f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        f.flush()
    return record


def read(stream: str) -> list[dict]:
    path = _path(stream)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def verify(stream: str) -> tuple[bool, str]:
    """Recompute the chain. Returns (ok, message)."""
    prev = GENESIS
    for n, rec in enumerate(read(stream), 1):
        claimed = rec.pop("hash")
        if rec["prev"] != prev:
            return False, f"{stream}: line {n} does not follow line {n - 1}"
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        if hashlib.sha256(body.encode()).hexdigest() != claimed:
            return False, f"{stream}: line {n} was modified"
        prev = claimed
    return True, f"{stream}: chain intact"


def streams() -> list[str]:
    return sorted(p.stem for p in config.EVIDENCE.glob("*.jsonl"))
