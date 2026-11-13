"""Detector: turns telemetry from outside the sessions into alerts, and
contains sessions automatically for high-severity alerts.

Telemetry sources (none of them written by the agent):
  kernel   VM kernel log: egress drops logged by the session's nftables table
  gateway  /var/log/fg/gateway/gateway.jsonl
  sink     /var/log/fg/sink/sink.jsonl (the attacker stand-in)
  delivery /var/log/fg/delivery/delivery.jsonl (scanner verdicts)

Every event is copied into the hash-chained "telemetry" evidence stream;
alerts go to the "alerts" stream with the user, session and action, and a
pointer (hash) to the telemetry record that triggered them.

Rules:
  EXFIL_SUCCESS     critical  a session's canary arrived at the sink
  GATEWAY_EGRESS_BLOCKED high the gateway itself tried a destination outside its policy
  EGRESS_BLOCKED    high      a session tried to reach a destination other than the gateway
  GATEWAY_ABUSE     high      denied endpoint, or a token presented from the wrong address
  DELIVERY_BLOCKED  high      the delivery scanner found the canary or a secret in agent code
  CANARY_TO_MODEL   medium    a canary appeared in a request to the model (allowed destination)
"""
import json
import os
import re
import subprocess
import threading
import time
from queue import Empty, Queue

from . import config, evidence, registry, session
from .canary import find_canaries

AUTO_CONTAIN = set(os.environ.get("FG_AUTO_CONTAIN", "critical,high").split(","))
DEDUP_SECONDS = 60
KERNEL_RE = re.compile(r"(fg-drop(?:-[a-z]+)?) s=(\w+) p=(\w+) .*?SRC=(\S+) DST=(\S+).*?PROTO=(\w+)(?:.*?DPT=(\d+))?")
GATEWAY_DROP_RE = re.compile(r"fg-drop-gw\S* .*?SRC=(\S+) DST=(\S+).*?PROTO=(\w+)(?:.*?DPT=(\d+))?")
FILES = {
    "gateway": config.LOGS / "gateway" / "gateway.jsonl",
    "sink": config.LOGS / "sink" / "sink.jsonl",
    "delivery": config.LOGS / "delivery" / "delivery.jsonl",
}


def session_for_ip(src_ip: str):
    m = re.fullmatch(rf"{re.escape(config.SUBNET_PREFIX)}\.(\d+)\.(\d+)", src_ip or "")
    if not m or int(m.group(2)) != config.RUNTIME_IP_SUFFIX:
        return None
    return registry.by_subnet(int(m.group(1)))


def kernel_reader(q: Queue):
    """Follow the VM kernel log from now on."""
    p = subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "json", "--no-pager"],
                         stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        try:
            msg = json.loads(line).get("MESSAGE", "")
        except ValueError:
            continue
        if isinstance(msg, str) and "fg-drop" in msg:
            q.put(("kernel", msg))


def file_reader(q: Queue):
    """Follow the JSONL logs from their current end."""
    offsets = {name: (p.stat().st_size if p.exists() else 0) for name, p in FILES.items()}
    while True:
        for name, path in FILES.items():
            if not path.exists():
                continue
            size = path.stat().st_size
            if size < offsets[name]:
                offsets[name] = 0
            if size > offsets[name]:
                with path.open() as f:
                    f.seek(offsets[name])
                    chunk = f.read()
                complete, _, _ = chunk.rpartition("\n")
                offsets[name] += len(complete) + 1 if complete else 0
                for line in complete.splitlines():
                    q.put((name, line))
        time.sleep(0.3)


class Detector:
    def __init__(self):
        self.recent = {}   # dedup key -> last alert time

    def handle(self, source: str, raw: str):
        ev = self.normalise(source, raw)
        if ev is None:
            return
        rec = evidence.append("telemetry", f"{source}:{ev['event']}", ev)
        for alert in self.rules(ev):
            self.raise_alert(alert, rec)

    def normalise(self, source: str, raw: str) -> dict | None:
        if source == "kernel":
            m = GATEWAY_DROP_RE.search(raw)
            if m:
                src, dst, proto, dport = m.groups()
                return {"source": "kernel", "event": "gateway_egress_dropped", "session": None, "src_ip": src,
                        "dst_ip": dst, "proto": proto, "dst_port": int(dport) if dport else None, "raw": raw}
            m = KERNEL_RE.search(raw)
            if not m:
                return None
            kind, sid, profile, src, dst, proto, dport = m.groups()
            return {"source": "kernel", "event": "egress_dropped", "session": sid, "policy": profile,
                    "kind": kind, "src_ip": src, "dst_ip": dst, "proto": proto,
                    "dst_port": int(dport) if dport else None, "raw": raw}
        try:
            ev = json.loads(raw)
        except ValueError:
            return None
        if source == "sink":
            s = session_for_ip(ev.get("src_ip"))
            ev["session"] = s["id"] if s else None
            text = " ".join([ev.get("path", ""), ev.get("body", ""), json.dumps(ev.get("headers", {}))])
            ev["canaries"] = find_canaries(text.encode(), {r["id"]: r["canary"] for r in registry.all_sessions()})
        if source == "gateway" and not ev.get("session"):
            s = session_for_ip(ev.get("src_ip"))
            ev["session"] = s["id"] if s else None
        return ev

    def rules(self, ev: dict) -> list[dict]:
        e, src = ev["event"], ev["source"]
        out = []
        if src == "sink" and ev.get("canaries"):
            for hit in ev["canaries"]:
                out.append({"rule": "EXFIL_SUCCESS", "severity": "critical",
                            "session": hit["canary_session"],
                            "action": {"what": "canary received by exfiltration sink", "encoding": hit["encoding"],
                                       "from_ip": ev["src_ip"], "sending_session": ev.get("session"),
                                       "request": f"{ev['method']} {ev['path']}"[:300]}})
        elif src == "kernel" and e == "gateway_egress_dropped":
            out.append({"rule": "GATEWAY_EGRESS_BLOCKED", "severity": "high", "session": None,
                        "dedup": (ev["dst_ip"], ev["dst_port"]),
                        "action": {"what": f"gateway tried {ev['proto']} to {ev['dst_ip']} port {ev['dst_port']} "
                                           "(possible gateway compromise)"}})
        elif src == "kernel" and ev["policy"] != "quarantine":
            dest = ev["dst_ip"] + (" (spoofed source)" if ev["kind"].endswith("spoof") else "")
            out.append({"rule": "EGRESS_BLOCKED", "severity": "high", "session": ev["session"],
                        "dedup": (ev["dst_ip"], ev["dst_port"], ev["proto"]),
                        "action": {"what": f"blocked {ev['proto']} to {dest} port {ev['dst_port']}",
                                   "dst_ip": ev["dst_ip"], "dst_port": ev["dst_port"], "proto": ev["proto"]}})
        elif src == "gateway" and e == "request_denied" and ev.get("session"):
            out.append({"rule": "GATEWAY_ABUSE", "severity": "high", "session": ev["session"],
                        "dedup": (e, ev.get("path")),
                        "action": {"what": f"gateway denied {ev.get('method')} {ev.get('path')}: {ev.get('reason')}"}})
        elif src == "gateway" and e == "auth_failed" and ev.get("session"):
            out.append({"rule": "GATEWAY_ABUSE", "severity": "high", "session": ev["session"],
                        "dedup": (e, ev.get("reason")),
                        "action": {"what": f"gateway rejected credentials: {ev.get('reason')}"}})
        elif src == "gateway" and e == "canary_in_request":
            out.append({"rule": "CANARY_TO_MODEL", "severity": "medium", "session": ev["session"],
                        "dedup": (e,),
                        "action": {"what": "canary sent to the model provider (allowed destination)",
                                   "encoding": ev.get("encoding"), "canary_owner": ev.get("canary_session")}})
        elif src == "delivery" and e == "delivery_blocked":
            out.append({"rule": "DELIVERY_BLOCKED", "severity": "high", "session": ev["session"],
                        "action": {"what": "agent code blocked before publishing", "findings": ev.get("findings")}})
        return out

    def raise_alert(self, alert: dict, telemetry_rec: dict):
        sid = alert["session"]
        key = (alert["rule"], sid, alert.pop("dedup", None))
        now = time.time()
        if now - self.recent.get(key, 0) < DEDUP_SECONDS:
            return
        self.recent[key] = now
        s = registry.get(sid) if sid else None
        alert.update({
            "user": s["user"] if s else None,
            "profile": s["profile"] if s else None,
            "session_state": s["state"] if s else "unknown",
            "observed_at": telemetry_rec["data"].get("ts", telemetry_rec["ts"]),
            "telemetry_record": telemetry_rec["hash"],
        })
        if alert["severity"] in AUTO_CONTAIN and s and s["state"] not in ("contained",):
            alert["containment"] = session.contain(sid, reason=f"{alert['rule']}: {alert['action']['what']}",
                                                   by="detector")
        evidence.append("alerts", alert["rule"], alert)
        print(json.dumps({"rule": alert["rule"], "severity": alert["severity"], "session": sid,
                          "user": alert["user"], "action": alert["action"]["what"],
                          "contained": alert.get("containment", {}).get("all_verified")}), flush=True)


def main():
    q: Queue = Queue()
    threading.Thread(target=kernel_reader, args=(q,), daemon=True).start()
    threading.Thread(target=file_reader, args=(q,), daemon=True).start()
    d = Detector()
    evidence.append("telemetry", "detector_started", {"auto_contain": sorted(AUTO_CONTAIN)})
    while True:
        try:
            source, raw = q.get(timeout=1)
        except Empty:
            continue
        try:
            d.handle(source, raw)
        except Exception as e:  # noqa: BLE001 - keep detecting
            evidence.append("telemetry", "detector_error", {"source": source, "error": str(e), "raw": raw[:500]})
