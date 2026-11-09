"""verify-export: completeness of a generic AI-product export, signed snapshots, and diff.

Layout: conversations*.json (list of objects with "id", or {"conversations": [...]}),
optional memories/ (one file per item, id = file stem) and attachments/ (id = file name).
Expected manifest: {"conversations": {"count": 3, "ids": ["a"]}, "memories": 2}.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
import unicodedata
import zipfile
from pathlib import Path

from . import core, crypto

KINDS = ("conversations", "memories", "attachments")
INV = "inventory.json"
# Zip-bomb guard, checked before anything is extracted.
MAX_MEMBERS = 100_000
MAX_MEMBER_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 8 * 1024**3


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


class Incomplete(core.EscrowError):
    code = 6


def _materialise(src: Path, td: Path) -> Path:
    src = Path(src)
    if src.is_file() and zipfile.is_zipfile(src):
        root = td / "unz"
        root.mkdir()
        with zipfile.ZipFile(src) as z:
            infos = z.infolist()
            if len(infos) > MAX_MEMBERS:
                raise core.UsageError(f"zip has {len(infos)} members > {MAX_MEMBERS}")
            declared = sum(i.file_size for i in infos)
            free = shutil.disk_usage(td).free
            if free < declared + 1024**3:
                raise core.UsageError(
                    f"insufficient disk: {free} bytes free, need declared {declared} + 1 GiB"
                )
            if declared > MAX_TOTAL_BYTES:
                raise core.UsageError(
                    f"zip declares more than {MAX_TOTAL_BYTES} bytes uncompressed"
                )
            for i in infos:
                t = (root / i.filename).resolve()
                if root.resolve() not in t.parents and t != root.resolve():
                    raise core.UsageError(f"unsafe path in zip: {i.filename}")
            total = 0
            for i in infos:  # bounded copy: a declared size can lie
                t = root / i.filename
                if i.is_dir():
                    t.mkdir(parents=True, exist_ok=True)
                    continue
                t.parent.mkdir(parents=True, exist_ok=True)
                n = 0
                with z.open(i) as fi, open(t, "wb") as fo:
                    while chunk := fi.read(1 << 20):
                        n += len(chunk)
                        total += len(chunk)
                        if n > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                            raise core.UsageError(
                                f"zip member {i.filename} inflates past the size cap"
                            )
                        fo.write(chunk)
        kids = list(root.iterdir())
        # unwrap one wrapper folder, but never a kind folder (attachments/ alone is content)
        if len(kids) == 1 and kids[0].is_dir() and kids[0].name not in KINDS:
            return kids[0]
        return root
    if src.is_dir():
        return src
    raise core.UsageError(f"not a directory or zip: {src}")


def inventory(root: Path) -> dict:
    inv = {k: [] for k in KINDS}
    for f in sorted(root.glob("conversations*.json")):
        try:
            d = core.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            raise core.UsageError(f"{f.name}: invalid JSON: {e}") from None
        if isinstance(d, dict):
            d = d.get("conversations", [])
        if not isinstance(d, list):
            raise core.UsageError(f"{f.name}: expected a list of conversations")
        for c in d:
            # only identified items count: placeholders ({} or junk) never satisfy a count
            cid = c.get("id") if isinstance(c, dict) else None
            if cid is not None and str(cid).strip():
                inv["conversations"].append(str(cid))
    for kind in ("memories", "attachments"):
        d = root / kind
        if d.is_dir():
            for p in sorted(x for x in d.rglob("*") if x.is_file()):
                inv[kind].append(
                    p.stem if kind == "memories" else p.relative_to(d).as_posix()
                )
    return {k: sorted({_nfc(x) for x in v}) for k, v in inv.items()}


def compare(inv: dict, expected: dict) -> dict:
    if not isinstance(expected, dict) or not expected:
        raise core.UsageError("expected manifest is empty: name at least one kind")
    unknown = sorted(set(expected) - set(KINDS))
    if unknown:
        raise core.UsageError(
            f"unknown kind(s) in expected manifest: {unknown}; use {list(KINDS)}"
        )
    rep = {}
    for kind, e in expected.items():
        if isinstance(e, int):
            e = {"count": e}
        if not isinstance(e, dict):
            raise core.UsageError(f"expected[{kind}] must be a count or object")
        found = set(inv.get(kind, []))
        ids = [_nfc(str(i)) for i in e.get("ids", [])]
        missing = sorted(set(ids) - found)
        exp = e.get("count", len(ids))
        n_missing = len(missing) if ids else max(0, exp - len(found))
        n_missing = max(n_missing, max(0, exp - len(found)))
        rep[kind] = {
            "expected": exp,
            "found": len(found),
            "missing_ids": missing,
            "missing": n_missing,
        }
    return rep


def verify(src: Path, expected_path: Path) -> tuple[dict, dict]:
    exp = core.loads(Path(expected_path).read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as td:
        inv = inventory(_materialise(src, Path(td)))
    return inv, compare(inv, exp)


def _hash_tree(root: Path) -> dict:
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def snapshot(
    src, snap: Path, beneficiary_pub: str, depositor_key: str, now=None
) -> dict:
    snap = Path(snap)
    with tempfile.TemporaryDirectory() as td:
        root = _materialise(src, Path(td))
        inv = inventory(root)
        if (snap / "export").exists():
            raise core.UsageError("snapshot dir already has an export/")
        shutil.copytree(root, snap / "export")
    inv_doc = {"items": inv, "files": _hash_tree(snap / "export")}
    text = json.dumps(inv_doc, indent=2, sort_keys=True) + "\n"
    with tempfile.TemporaryDirectory() as td:
        art = Path(td) / "art"
        art.mkdir()
        (art / INV).write_bytes(text.encode())
        with tarfile.open(art / "export.tar", "w") as t:
            t.add(snap / "export", arcname="export")
        tpl = {
            "depositor": {"name": "export-snapshot"},
            "artefact_kinds": {INV: "history", "export.tar": "history"},
            "holder": {"name": "local", "pubkey": crypto.gen_keypair("ed25519")[1]},
        }
        m = core.deposit(tpl, art, beneficiary_pub, depositor_key, snap, now)
    (snap / INV).write_bytes(text.encode())
    return m


def load_snapshot(snap: Path, expect_keyid: str, now=None, with_time: bool = False):
    """check() (signatures, ciphertext hashes), then bind plaintext inventory + export/ to the manifest."""
    snap = Path(snap)
    core.check(snap / "manifest.json", now, expect_keyid)
    m = core.loads((snap / "manifest.json").read_text())
    want = next(a for a in m["artefacts"] if a["name"] == INV)["plaintext_sha256"]
    ip = snap / INV
    if not ip.is_file() or hashlib.sha256(ip.read_bytes()).hexdigest() != want:
        raise core.Tamper("snapshot inventory does not match signed manifest")
    doc = core.loads(ip.read_text())
    if not (snap / "export").is_dir() or _hash_tree(snap / "export") != doc["files"]:
        raise core.Tamper("snapshot export/ does not match signed inventory")
    return (doc["items"], m["created_at"]) if with_time else doc["items"]


def ordered_pair(
    old: Path, new: Path, expect_keyid: str, now=None
) -> tuple[dict, dict]:
    """Both verified, and NEW signed strictly after OLD; else a replayed old snapshot reads NO LOSS."""
    a, ta = load_snapshot(old, expect_keyid, now, with_time=True)
    b, tb = load_snapshot(new, expect_keyid, now, with_time=True)
    if not core.parse_iso(tb) > core.parse_iso(ta):
        raise core.UsageError(
            f"snapshot order: NEW ({tb}) is not strictly after OLD ({ta})"
        )
    return a, b


def diff(old: dict, new: dict) -> dict:
    return {
        k: sorted(set(old.get(k, [])) - set(new.get(k, [])))
        for k in sorted(set(old) | set(new))
    }
