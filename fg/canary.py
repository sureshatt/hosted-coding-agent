"""Canary matching, shared by the detector and the delivery scanner.

The gateway carries its own copy (services/gateway.py) because it runs in a
separate container from a separate code path; keep the two in step.
"""
import base64
import binascii
import urllib.parse


def forms(canary: str) -> dict[str, bytes]:
    """The canary and common encodings an agent might use to disguise it."""
    raw = canary.encode()
    out = {"plain": raw, "hex": binascii.hexlify(raw), "url": urllib.parse.quote(canary, safe="").encode()}
    # base64 of the canary at each of the three possible alignments inside a
    # larger encoded string; drop the edge characters that depend on neighbours.
    for shift in range(3):
        enc = base64.b64encode(b"\0" * shift + raw)[(shift * 4 + 2) // 3:]
        out[f"base64/{shift}"] = enc[: len(enc) - 4]
        out[f"base64url/{shift}"] = enc[: len(enc) - 4].replace(b"+", b"-").replace(b"/", b"_")
    return out


def find_canaries(data: bytes, canaries: dict[str, str]) -> list[dict]:
    """canaries: {session_id: canary}. Returns one hit per session found."""
    hits = []
    lowered = data.lower()
    for sid, canary in canaries.items():
        for form, needle in forms(canary).items():
            # hex may be written in either case; the others are case-sensitive
            if needle and (needle in data or (form == "hex" and needle.lower() in lowered)):
                hits.append({"canary_session": sid, "encoding": form})
                break
    return hits
