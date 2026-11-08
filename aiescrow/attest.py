"""attest-spec v1 writer: DSSE envelope over an in-toto Statement v1 (see attest-spec/SPEC.md)."""

import base64
import hashlib
import json
import platform

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__

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
    payload = json.dumps(
        stmt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
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
