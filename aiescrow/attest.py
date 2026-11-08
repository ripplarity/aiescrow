"""attest-spec v1 writer: DSSE envelope over an in-toto Statement v1 (see attest-spec/SPEC.md)."""

import base64
import hashlib
import json
import platform

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__

MAX_INT = 2**53 - 1


def jcs(o) -> bytes:
    """RFC 8785 canonical JSON, restricted to str/int/bool/null/list/dict (no floats)."""
    return _jcs(o).encode("utf-8")


def _jcs(o) -> str:
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        if abs(o) > MAX_INT:
            raise ValueError("integer outside +-(2^53-1)")
        return str(o)
    if isinstance(o, float):
        raise ValueError("floats are not allowed in attestation JSON")
    if isinstance(o, str):
        o.encode("utf-8")
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list):
        return "[" + ",".join(_jcs(v) for v in o) + "]"
    if isinstance(o, dict):
        keys = sorted(o, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs(k) + ":" + _jcs(o[k]) for k in keys) + "}"
    raise ValueError(f"unsupported type {type(o).__name__}")


PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://ripplarity.com/attestation/aiescrow/manifest/v1"


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def keyid_from_pub_hex(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


def manifest_envelope(
    manifest: dict, manifest_bytes: bytes, priv_hex: str, started: str, ended: str
) -> dict:
    """manifest_bytes are the exact bytes of manifest.json (the attestation subject)."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "manifest.json",
                "digest": {"sha256": hashlib.sha256(manifest_bytes).hexdigest()},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "producer": {"tool": "aiescrow", "version": __version__},
            "started": started,
            "ended": ended,
            "environment": {
                "host_os": platform.system().lower(),
                "run_mode": "REAL",
            },
            "escrow_id": manifest["escrow_id"],
            "depositor_pubkey": manifest["depositor"]["pubkey"],
            "artefact_count": len(manifest["artefacts"]),
        },
    }
    payload = jcs(stmt)
    sig = key.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": hashlib.sha256(raw).hexdigest(),
                "sig": base64.b64encode(sig).decode(),
            }
        ],
    }
