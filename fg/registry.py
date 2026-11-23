"""Session registry: who started which session, and what it is made of.

The detector uses it to turn "packet from 10.250.3.10" or "request with
token X" into "user U, session S".
"""
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user        TEXT NOT NULL,
  profile     TEXT NOT NULL,
  subnet_n    INTEGER NOT NULL UNIQUE,
  canary      TEXT NOT NULL,
  token_hash  TEXT NOT NULL,
  task        TEXT,
  repo        TEXT NOT NULL DEFAULT 'invoice-clean',
  state       TEXT NOT NULL,
  created     REAL NOT NULL,
  updated     REAL NOT NULL
);
"""


@contextmanager
def db():
    config.STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(config.REGISTRY_DB, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


def allocate_subnet(conn) -> int:
    used = {r[0] for r in conn.execute("SELECT subnet_n FROM sessions")}
    for n in range(1, 250):
        if n not in used:
            return n
    raise RuntimeError("no free session subnets")


def add(conn, **s):
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (id, user, profile, subnet_n, canary, token_hash, task, repo, state, created, updated)"
        " VALUES (:id, :user, :profile, :subnet_n, :canary, :token_hash, :task, :repo, :state, :now, :now)",
        {**s, "now": now},
    )


def set_state(sid: str, state: str):
    with db() as conn:
        conn.execute("UPDATE sessions SET state=?, updated=? WHERE id=?", (state, time.time(), sid))


def get(sid: str):
    with db() as conn:
        return conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()


def all_sessions():
    with db() as conn:
        return conn.execute("SELECT * FROM sessions ORDER BY created").fetchall()


def by_subnet(n: int):
    with db() as conn:
        return conn.execute("SELECT * FROM sessions WHERE subnet_n=?", (n,)).fetchone()


def remove(sid: str):
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE id=?", (sid,))


def ip(n: int, suffix: int) -> str:
    return f"{config.SUBNET_PREFIX}.{n}.{suffix}"
