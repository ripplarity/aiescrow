"""Manifest model and deposit / heartbeat / check / release / open logic."""

from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import crypto
from .holder import GitHolder, LocalHolder

DEFAULT_INTERVAL_DAYS = 90
DEFAULT_GRACE_DAYS = 30


class Kind(str, Enum):
    model_weights = "model_weights"
    fine_tune = "fine_tune"
    memory = "memory"
    history = "history"
    config = "config"
    other = "other"


class Artefact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    kind: Kind
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    plaintext_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    encryption: Literal["age", "x25519"]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal[
        "vendor_shutdown", "acquisition", "deprecation", "deadman", "court_order"
    ]
    params: dict[str, Any] = Field(default_factory=dict)


class Party(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    pubkey: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    type: str | None = None


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["depositor"]
    pubkey: str = Field(pattern=r"^[0-9a-f]{64}$")
    sig: str = Field(pattern=r"^[0-9a-f]{128}$")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    escrow_id: str
    depositor: Party
    beneficiary_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str
    artefacts: list[Artefact] = Field(min_length=1)
    release_conditions: list[Condition] = Field(min_length=1)
    holder: Party
    signatures: list[Signature]


class EscrowError(Exception):
    code = 1


class Tamper(EscrowError):
    code = 4


class Expired(EscrowError):
    code = 3


class NotReleasable(EscrowError):
    code = 5


def now_utc(now: str | None = None) -> datetime:
    """UTC time. `now` is a TEST-ONLY override (ISO-8601)."""
    if now:
        d = datetime.fromisoformat(now.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _signed_body(m: dict) -> bytes:
    return canon({k: v for k, v in m.items() if k != "signatures"})


def read_key(v: str) -> str:
    """Key as hex string or path to a file holding hex."""
    p = Path(v)
    try:
        if p.is_file():
            return p.read_text().strip()
    except OSError:
        pass
    return v.strip()


def _holder(root: Path, git: bool):
    return GitHolder(root) if git else LocalHolder(root)


def deposit(
    template: dict,
    artefacts_dir: Path,
    beneficiary_pub: str,
    depositor_priv: str,
    out: Path,
    now: str | None = None,
    git: bool = False,
) -> dict:
    t = now_utc(now)
    h = _holder(out, git)
    kinds = template.get("artefact_kinds", {})
    entries = []
    with tempfile.TemporaryDirectory() as td:
        for f in sorted(p for p in Path(artefacts_dir).iterdir() if p.is_file()):
            enc = Path(td) / (f.name + ".age")
            r = crypto.encrypt_file(f, enc, beneficiary_pub)
            h.put(enc, f"artefacts/{f.name}.age")
            entries.append(
                {
                    "name": f.name,
                    "kind": kinds.get(f.name, "other"),
                    "sha256": r["sha256"],
                    "size": r["size"],
                    "plaintext_sha256": r["plain_sha256"],
                    "encryption": "x25519",
                }
            )
    if not entries:
        raise EscrowError("no artefacts found")
    dpub = crypto.ed_pub_from_priv(depositor_priv)
    m = {
        "escrow_id": template.get("escrow_id") or str(uuid.uuid4()),
        "depositor": {**template.get("depositor", {"name": "unknown"}), "pubkey": dpub},
        "beneficiary_id_hash": hashlib.sha256(
            bytes.fromhex(beneficiary_pub)
        ).hexdigest(),
        "created_at": iso(t),
        "artefacts": entries,
        "release_conditions": template.get("release_conditions")
        or [
            {
                "type": "deadman",
                "params": {
                    "interval_days": DEFAULT_INTERVAL_DAYS,
                    "grace_days": DEFAULT_GRACE_DAYS,
                },
            }
        ],
        "holder": template.get("holder", {"name": "local"}),
        "signatures": [],
    }
    m["signatures"] = [
        {
            "role": "depositor",
            "pubkey": dpub,
            "sig": crypto.sign(depositor_priv, _signed_body(m)),
        }
    ]
    Manifest.model_validate(m)
    _put_json(h, "manifest.json", m)
    heartbeat(out, depositor_priv, now=now, git=git)
    return m


def _put_json(h, name: str, obj: dict):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.json"
        p.write_text(json.dumps(obj, indent=2) + "\n")
        h.put(p, name)


def _interval(
    m: dict, key: str = "interval_days", default: int = DEFAULT_INTERVAL_DAYS
) -> int:
    for c in m["release_conditions"]:
        if c["type"] == "deadman":
            return int(c.get("params", {}).get(key, default))
    return default


def heartbeat(
    root: Path, depositor_priv: str, now: str | None = None, git: bool = False
) -> dict:
    root = Path(root)
    m = json.loads((root / "manifest.json").read_text())
    if crypto.ed_pub_from_priv(depositor_priv) != m["depositor"]["pubkey"]:
        raise EscrowError("key does not match manifest depositor")
    body = {"escrow_id": m["escrow_id"], "timestamp": iso(now_utc(now))}
    hb = {
        **body,
        "pubkey": m["depositor"]["pubkey"],
        "sig": crypto.sign(depositor_priv, canon(body)),
    }
    _put_json(_holder(root, git), "heartbeat.json", hb)
    return hb


def check(manifest_path: Path, now: str | None = None) -> dict:
    """Raises Tamper (4) or Expired (3). Returns a status dict on success."""
    mp = Path(manifest_path)
    root = mp.parent
    try:
        raw = json.loads(mp.read_text())
        Manifest.model_validate(raw)
    except Exception as e:
        raise Tamper(f"manifest invalid: {e}") from None
    sigs = raw["signatures"]
    if not any(
        s["role"] == "depositor"
        and s["pubkey"] == raw["depositor"]["pubkey"]
        and crypto.verify(s["pubkey"], s["sig"], _signed_body(raw))
        for s in sigs
    ):
        raise Tamper("manifest signature invalid")
    for a in raw["artefacts"]:
        p = root / "artefacts" / (a["name"] + ".age")
        if not p.is_file():
            raise Tamper(f"missing artefact {a['name']}")
        if p.stat().st_size != a["size"] or crypto.sha256_file(p) != a["sha256"]:
            raise Tamper(f"artefact {a['name']} does not match manifest")
    hp = root / "heartbeat.json"
    if not hp.is_file():
        raise Expired("no heartbeat")
    hb = json.loads(hp.read_text())
    if (
        hb.get("escrow_id") != raw["escrow_id"]
        or hb.get("pubkey") != raw["depositor"]["pubkey"]
        or not crypto.verify(
            hb["pubkey"],
            hb["sig"],
            canon({"escrow_id": hb["escrow_id"], "timestamp": hb["timestamp"]}),
        )
    ):
        raise Tamper("heartbeat signature invalid")
    age = now_utc(now) - now_utc(hb["timestamp"])
    limit = timedelta(days=_interval(raw))
    if age > limit:
        raise Expired(f"heartbeat expired: age {age.days}d > {limit.days}d")
    return {
        "escrow_id": raw["escrow_id"],
        "artefacts": len(raw["artefacts"]),
        "heartbeat_age_days": age.days,
    }


def release(
    root: Path,
    condition: str,
    holder_priv: str,
    now: str | None = None,
    attestation: str = "",
    git: bool = False,
) -> dict:
    root = Path(root)
    m = json.loads((root / "manifest.json").read_text())
    try:
        check(root / "manifest.json", now=now)
        hb_expired = False
    except Expired:
        hb_expired = True
    declared = {c["type"] for c in m["release_conditions"]}
    t = now_utc(now)
    rec = {
        "escrow_id": m["escrow_id"],
        "condition": condition,
        "released_at": iso(t),
        "manifest_sha256": hashlib.sha256(_signed_body(m)).hexdigest(),
        "holder_attestation": attestation,
    }
    if condition == "deadman":
        if "deadman" not in declared:
            raise NotReleasable("deadman not a declared release condition")
        if not hb_expired:
            raise NotReleasable("heartbeat is still fresh; deadman not triggered")
        hb = json.loads((root / "heartbeat.json").read_text())
        rec["holder_attestation"] = attestation or (
            f"holder observed no valid heartbeat since {hb['timestamp']}"
        )
        base = now_utc(hb["timestamp"]) + timedelta(days=_interval(m))
        rec["contest_until"] = iso(
            base + timedelta(days=_interval(m, "grace_days", DEFAULT_GRACE_DAYS))
        )
    elif condition == "shutdown":
        if "vendor_shutdown" not in declared:
            raise NotReleasable("vendor_shutdown not a declared release condition")
        if not attestation:
            raise NotReleasable("shutdown release requires --attestation")
    else:
        raise NotReleasable(f"unknown condition {condition}")
    rec["pubkey"] = crypto.ed_pub_from_priv(holder_priv)
    rec["sig"] = crypto.sign(
        holder_priv, canon({k: v for k, v in rec.items() if k != "sig"})
    )
    _put_json(_holder(root, git), "release.json", rec)
    return rec


def open_release(
    root: Path, beneficiary_priv: str, out: Path, now: str | None = None
) -> list[dict]:
    root = Path(root)
    rp = root / "release.json"
    if not rp.is_file():
        raise NotReleasable("no release record; nothing to open")
    rec = json.loads(rp.read_text())
    if not crypto.verify(
        rec["pubkey"], rec["sig"], canon({k: v for k, v in rec.items() if k != "sig"})
    ):
        raise Tamper("release record signature invalid")
    m = json.loads((root / "manifest.json").read_text())
    hp = m["holder"].get("pubkey")
    if hp and hp != rec["pubkey"]:
        raise Tamper("release signed by a key other than the manifest holder")
    if rec["manifest_sha256"] != hashlib.sha256(_signed_body(m)).hexdigest():
        raise Tamper("release record does not match manifest")
    if rec.get("contest_until") and now_utc(now) < now_utc(rec["contest_until"]):
        raise NotReleasable(f"contest window open until {rec['contest_until']}")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for a in m["artefacts"]:
        try:
            got = crypto.decrypt_file(
                root / "artefacts" / (a["name"] + ".age"),
                out / a["name"],
                beneficiary_priv,
            )
        except crypto.CryptoError as e:
            raise EscrowError(
                f"cannot open {a['name']}: {e} (lost beneficiary key? "
                "recovery is out of scope for v0.1)"
            ) from None
        ok = a.get("plaintext_sha256") in (None, got)
        if not ok:
            raise Tamper(f"hash mismatch for {a['name']}")
        results.append({"name": a["name"], "sha256": got})
    return results
