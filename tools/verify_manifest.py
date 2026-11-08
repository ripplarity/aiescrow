#!/usr/bin/env python3
"""Standalone User-State Escrow v0.1 verifier (stdlib + cryptography only).

Usage: python verify_manifest.py <manifest.json> --expect-keyid <hex>
Checks that the depositor key matches the pinned keyid (sha256 of the raw public key),
every signatures[] entry verifies under it, duplicate JSON keys are rejected, and every artefact size/sha256 (artefacts/<name>.x25519
next to the manifest). Exit 0 valid, 4 tamper/invalid. No aiescrow install needed.
"""
import hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main(argv):
    if len(argv) != 4 or argv[2] != "--expect-keyid":
        print(__doc__)
        return 2
    mp = Path(argv[1])
    try:
        def nodup(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError(f"duplicate JSON key {k}")
                d[k] = v
            return d

        m = json.loads(mp.read_text(), object_pairs_hook=nodup)
        pin = argv[3].strip().lower()
        body = json.dumps({k: v for k, v in m.items() if k != "signatures"},
                          sort_keys=True, separators=(",", ":")).encode()
        dep = m["depositor"]["pubkey"]
        ok = bool(m["signatures"]) and hashlib.sha256(bytes.fromhex(dep)).hexdigest() == pin
        for s in m["signatures"]:
            try:
                if s["role"] != "depositor" or hashlib.sha256(bytes.fromhex(s["pubkey"])).hexdigest() != pin:
                    raise ValueError
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(s["pubkey"])).verify(
                    bytes.fromhex(s["sig"]), body)
            except Exception:
                ok = False
        if not ok:
            print("FAIL: manifest signature invalid")
            return 4
        for a in m["artefacts"]:
            p = mp.parent / "artefacts" / (a["name"] + ".x25519")
            if not p.is_file() or p.stat().st_size != a["size"]:
                print(f"FAIL: artefact {a['name']} missing or wrong size")
                return 4
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while b := f.read(1 << 20):
                    h.update(b)
            if h.hexdigest() != a["sha256"]:
                print(f"FAIL: artefact {a['name']} hash mismatch")
                return 4
    except (KeyError, ValueError, OSError) as e:
        print(f"FAIL: {e}")
        return 4
    print(f"VERIFIED {m['escrow_id']} ({len(m['artefacts'])} artefacts)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
