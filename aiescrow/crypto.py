"""Chunked X25519 + ChaCha20-Poly1305 file encryption and ed25519 signing.

File format: MAGIC | eph_pub(32) | wrap_nonce(12) | wrapped_key(48) | nonce_prefix(4)
then chunks of [u32 ciphertext_len][ciphertext]; nonce = prefix||u64 index;
AAD = u64 index || final-flag (so truncation/reorder/append fail).
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"AIE1"
CHUNK = 1024 * 1024
TAG = 16
HDR = len(MAGIC) + 32 + 12 + 48 + 4


class CryptoError(Exception):
    pass


def _raw_priv(k) -> bytes:
    return k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_pub(k) -> bytes:
    return k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _pub_bytes(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def gen_keypair(kind: str) -> tuple[str, str]:
    """Return (private_hex, public_hex)."""
    k = (
        Ed25519PrivateKey.generate()
        if kind == "ed25519"
        else X25519PrivateKey.generate()
    )
    return _raw_priv(k).hex(), _raw_pub(k).hex()


def sign(priv_hex: str, data: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(data).hex()
    )


def verify(pub_hex: str, sig_hex: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), data
        )
        return True
    except Exception:
        return False


def ed_pub_from_priv(priv_hex: str) -> str:
    return _raw_pub(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))).hex()


def _kek(shared: bytes, eph_pub: bytes, ben_pub: bytes) -> bytes:
    return HKDF(
        hashes.SHA256(), 32, salt=eph_pub + ben_pub, info=b"aiescrow-v0.1-wrap"
    ).derive(shared)


def _aad(i: int, final: bool) -> bytes:
    return struct.pack(">QB", i, 1 if final else 0)


def encrypt_file(src: Path, dst: Path, beneficiary_pub_hex: str) -> dict:
    """Stream-encrypt src to dst in 1 MiB chunks. Returns hashes and sizes."""
    ben = bytes.fromhex(beneficiary_pub_hex)
    eph = X25519PrivateKey.generate()
    eph_pub = _raw_pub(eph)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(ben))
    ck = os.urandom(32)
    wn = os.urandom(12)
    wrapped = ChaCha20Poly1305(_kek(shared, eph_pub, ben)).encrypt(wn, ck, MAGIC)
    prefix = os.urandom(4)
    aead = ChaCha20Poly1305(ck)
    ph, ch = hashlib.sha256(), hashlib.sha256()
    psize = 0
    with open(src, "rb") as f, open(dst, "wb") as o:
        head = MAGIC + eph_pub + wn + wrapped + prefix
        o.write(head)
        ch.update(head)
        cur = f.read(CHUNK)
        i = 0
        while True:
            nxt = f.read(CHUNK)
            final = not nxt
            ph.update(cur)
            psize += len(cur)
            ct = aead.encrypt(prefix + struct.pack(">Q", i), cur, _aad(i, final))
            rec = struct.pack(">I", len(ct)) + ct
            o.write(rec)
            ch.update(rec)
            if final:
                break
            cur, i = nxt, i + 1
    return {
        "plain_sha256": ph.hexdigest(),
        "plain_size": psize,
        "sha256": ch.hexdigest(),
        "size": dst.stat().st_size,
    }


def decrypt_file(src: Path, dst: Path, beneficiary_priv_hex: str) -> str:
    """Stream-decrypt; returns plaintext sha256. Raises CryptoError on any failure."""
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(beneficiary_priv_hex))
    ben_pub = _raw_pub(priv)
    try:
        with open(src, "rb") as f, open(dst, "wb") as o:
            h = f.read(HDR)
            if len(h) != HDR or h[:4] != MAGIC:
                raise CryptoError("bad header")
            eph_pub, wn, wrapped, prefix = h[4:36], h[36:48], h[48:96], h[96:100]
            shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
            ck = ChaCha20Poly1305(_kek(shared, eph_pub, ben_pub)).decrypt(
                wn, wrapped, MAGIC
            )
            aead = ChaCha20Poly1305(ck)
            ph = hashlib.sha256()
            i = 0
            while True:
                lb = f.read(4)
                if len(lb) != 4:
                    raise CryptoError("truncated")
                n = struct.unpack(">I", lb)[0]
                if n < TAG or n > CHUNK + TAG:
                    raise CryptoError("bad chunk length")
                ct = f.read(n)
                if len(ct) != n:
                    raise CryptoError("truncated")
                final = f.peek(1)[:1] == b""
                pt = aead.decrypt(prefix + struct.pack(">Q", i), ct, _aad(i, final))
                o.write(pt)
                ph.update(pt)
                if final:
                    return ph.hexdigest()
                i += 1
    except InvalidTag:
        raise CryptoError("decryption failed (wrong key or tampered data)") from None
    except ValueError as e:
        raise CryptoError(f"decryption failed: {e}") from None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while b := f.read(CHUNK):
            h.update(b)
    return h.hexdigest()
