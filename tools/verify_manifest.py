#!/usr/bin/env python3
"""Standalone User-State Escrow v0.1 verifier (stdlib + cryptography only).

Usage: python verify_manifest.py <manifest.json>
Checks the depositor signature and every artefact size/sha256 (artefacts/<name>.x25519
next to the manifest). Exit 0 valid, 4 tamper/invalid. No aiescrow install needed.
"""
import hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    mp = Path(argv[1])
    try:
        m = json.loads(mp.read_text())
        body = json.dumps({k: v for k, v in m.items() if k != "signatures"},
                          sort_keys=True, separators=(",", ":")).encode()
        dep = m["depositor"]["pubkey"]
        ok = False
        for s in m["signatures"]:
            if s["role"] == "depositor" and s["pubkey"] == dep:
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(dep)).verify(
                        bytes.fromhex(s["sig"]), body)
                    ok = True
                except Exception:
                    pass
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
