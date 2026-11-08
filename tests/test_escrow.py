import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
from aiescrow import core, crypto
from aiescrow.cli import app
from aiescrow.holder import GitHolder, LocalHolder
from pydantic import ValidationError
from typer.testing import CliRunner

SCHEMA = Path(__file__).parent.parent / "schema" / "manifest.schema.json"
T0 = "2026-01-01T00:00:00Z"


@pytest.fixture
def env(tmp_path):
    vp, vpub = crypto.gen_keypair("ed25519")
    hp, hpub = crypto.gen_keypair("ed25519")
    bp, bpub = crypto.gen_keypair("x25519")
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "memories.jsonl").write_text('{"a":1}\n')
    (plain / "w.bin").write_bytes(os.urandom(5000))
    out = tmp_path / "out"
    tpl = {
        "depositor": {"name": "v"},
        "holder": {"name": "h"},
        "artefact_kinds": {"w.bin": "fine_tune", "memories.jsonl": "memory"},
        "release_conditions": [
            {"type": "deadman", "params": {"interval_days": 90, "grace_days": 30}},
            {"type": "vendor_shutdown"},
        ],
    }
    m = core.deposit(tpl, plain, bpub, vp, out, now=T0)
    return dict(vp=vp, hp=hp, bp=bp, bpub=bpub, plain=plain, out=out, m=m, tmp=tmp_path)


def test_schema_file_matches_model():
    s = json.loads(SCHEMA.read_text())
    required = {n for n, f in core.Manifest.model_fields.items() if f.is_required()}
    assert set(s["required"]) == required
    assert set(s["properties"]) == set(core.Manifest.model_fields)


def test_good_manifest_validates(env):
    core.Manifest.model_validate(json.loads((env["out"] / "manifest.json").read_text()))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("holder"),
        lambda m: m["artefacts"][0].update(kind="bogus"),
        lambda m: m["artefacts"][0].update(sha256="xyz"),
        lambda m: m["release_conditions"][0].update(type="nope"),
    ],
)
def test_bad_manifests_rejected(env, mutate):
    m = copy.deepcopy(env["m"])
    mutate(m)
    with pytest.raises(ValidationError):
        core.Manifest.model_validate(m)


def test_roundtrip(tmp_path):
    priv, pub = crypto.gen_keypair("x25519")
    src = tmp_path / "s"
    src.write_bytes(os.urandom(3 * 1024 * 1024 + 17))
    r = crypto.encrypt_file(src, tmp_path / "e", pub)
    got = crypto.decrypt_file(tmp_path / "e", tmp_path / "d", priv)
    assert (
        got == r["plain_sha256"] and (tmp_path / "d").read_bytes() == src.read_bytes()
    )


def test_empty_file_roundtrip(tmp_path):
    priv, pub = crypto.gen_keypair("x25519")
    (tmp_path / "s").write_bytes(b"")
    crypto.encrypt_file(tmp_path / "s", tmp_path / "e", pub)
    crypto.decrypt_file(tmp_path / "e", tmp_path / "d", priv)
    assert (tmp_path / "d").read_bytes() == b""


def test_large_file_20mb(tmp_path):
    priv, pub = crypto.gen_keypair("x25519")
    src = tmp_path / "big"
    with open(src, "wb") as f:
        f.writelines(os.urandom(1024 * 1024) for _ in range(20))
    r = crypto.encrypt_file(src, tmp_path / "e", pub)
    assert r["size"] > 20 * 1024 * 1024
    assert (
        crypto.decrypt_file(tmp_path / "e", tmp_path / "d", priv) == r["plain_sha256"]
    )


def test_wrong_key_fails(tmp_path):
    _, pub = crypto.gen_keypair("x25519")
    other, _ = crypto.gen_keypair("x25519")
    (tmp_path / "s").write_bytes(b"secret")
    crypto.encrypt_file(tmp_path / "s", tmp_path / "e", pub)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_file(tmp_path / "e", tmp_path / "d", other)


def test_check_passes(env):
    assert (
        core.check(env["out"] / "manifest.json", now="2026-02-01T00:00:00Z")[
            "artefacts"
        ]
        == 2
    )


def test_tamper_artefact_append(env):
    with open(env["out"] / "artefacts" / "memories.jsonl.x25519", "ab") as f:
        f.write(b"x\n")
    with pytest.raises(core.Tamper):
        core.check(env["out"] / "manifest.json", now=T0)


def test_tamper_manifest(env):
    p = env["out"] / "manifest.json"
    m = json.loads(p.read_text())
    m["depositor"]["name"] = "evil"
    p.write_text(json.dumps(m))
    with pytest.raises(core.Tamper):
        core.check(p, now=T0)


def test_truncated_ciphertext_detected_on_open(tmp_path):
    priv, pub = crypto.gen_keypair("x25519")
    s = tmp_path / "s"
    s.write_bytes(os.urandom(2 * 1024 * 1024 + 5))
    crypto.encrypt_file(s, tmp_path / "e", pub)
    data = (tmp_path / "e").read_bytes()
    first_chunk_end = crypto.HDR + 4 + crypto.CHUNK + crypto.TAG
    (tmp_path / "e").write_bytes(data[:first_chunk_end])  # drop later chunks cleanly
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_file(tmp_path / "e", tmp_path / "d", priv)


def test_heartbeat_expiry_with_now(env):
    with pytest.raises(core.Expired):
        core.check(env["out"] / "manifest.json", now="2026-05-01T00:00:00Z")
    core.heartbeat(env["out"], env["vp"], now="2026-05-01T00:00:00Z")
    core.check(env["out"] / "manifest.json", now="2026-05-02T00:00:00Z")


def test_heartbeat_wrong_key_refused(env):
    other, _ = crypto.gen_keypair("ed25519")
    with pytest.raises(core.EscrowError):
        core.heartbeat(env["out"], other, now=T0)


def test_release_refused_while_fresh(env):
    with pytest.raises(core.NotReleasable):
        core.release(env["out"], "deadman", env["hp"], now="2026-02-01T00:00:00Z")


def test_release_signature_and_open(env):
    rec = core.release(env["out"], "deadman", env["hp"], now="2026-06-01T00:00:00Z")
    assert (
        rec["condition"] == "deadman"
        and rec["holder_attestation"]
        and rec["contest_until"]
    )
    body = {k: v for k, v in rec.items() if k != "sig"}
    assert crypto.verify(rec["pubkey"], rec["sig"], core.canon(body))
    res = core.open_release(
        env["out"], env["bp"], env["tmp"] / "r", now="2026-07-01T00:00:00Z"
    )
    assert {r["name"] for r in res} == {"w.bin", "memories.jsonl"}
    assert (env["tmp"] / "r" / "w.bin").read_bytes() == (
        env["plain"] / "w.bin"
    ).read_bytes()


def test_open_blocked_during_contest_window(env):
    core.release(env["out"], "deadman", env["hp"], now="2026-04-10T00:00:00Z")
    with pytest.raises(core.NotReleasable):
        core.open_release(
            env["out"], env["bp"], env["tmp"] / "r", now="2026-04-11T00:00:00Z"
        )


def test_forged_release_rejected(env):
    core.release(env["out"], "deadman", env["hp"], now="2026-06-01T00:00:00Z")
    p = env["out"] / "release.json"
    r = json.loads(p.read_text())
    r["released_at"] = "2020-01-01T00:00:00Z"
    p.write_text(json.dumps(r))
    with pytest.raises(core.Tamper):
        core.open_release(
            env["out"], env["bp"], env["tmp"] / "r", now="2026-07-01T00:00:00Z"
        )


def test_open_without_release_and_wrong_key(env):
    with pytest.raises(core.NotReleasable):
        core.open_release(env["out"], env["bp"], env["tmp"] / "r")
    core.release(
        env["out"],
        "shutdown",
        env["hp"],
        now=T0,
        attestation="vendor announced closure",
    )
    other, _ = crypto.gen_keypair("x25519")
    with pytest.raises(core.EscrowError, match="recovery is out of scope"):
        core.open_release(env["out"], other, env["tmp"] / "r2", now=T0)


def test_shutdown_requires_attestation(env):
    with pytest.raises(core.NotReleasable):
        core.release(env["out"], "shutdown", env["hp"], now=T0)


def test_local_holder_interface_and_escape(tmp_path):
    h = LocalHolder(tmp_path / "h")
    (tmp_path / "f").write_text("hi")
    h.put(tmp_path / "f", "a/f")
    assert h.get("a/f") == b"hi" and h.list() == ["a/f"]
    with pytest.raises(ValueError):
        h.put(tmp_path / "f", "../escape")


def test_git_holder_roundtrip(tmp_path):
    h = GitHolder(tmp_path / "repo")
    (tmp_path / "f").write_text("v1")
    h.put(tmp_path / "f", "x.txt")
    (tmp_path / "f").write_text("v2")
    h.put(tmp_path / "f", "x.txt")
    assert h.get("x.txt") == b"v2" and h.list() == ["x.txt"]
    assert h.log() == ["put x.txt", "put x.txt"]


def test_full_flow_on_git_holder(tmp_path):
    vp, _ = crypto.gen_keypair("ed25519")
    hp, _ = crypto.gen_keypair("ed25519")
    bp, bpub = crypto.gen_keypair("x25519")
    plain = tmp_path / "p"
    plain.mkdir()
    (plain / "m.jsonl").write_text("{}\n")
    out = tmp_path / "repo"
    core.deposit(
        {"depositor": {"name": "v"}, "holder": {"name": "g", "type": "git"}},
        plain,
        bpub,
        vp,
        out,
        now=T0,
        git=True,
    )
    core.check(out / "manifest.json", now=T0)
    log = subprocess.run(
        ["git", "log", "--format=%s"], cwd=out, capture_output=True, text=True
    ).stdout
    assert "put manifest.json" in log and "put heartbeat.json" in log


def test_cli_smoke(tmp_path):
    r = CliRunner()
    k = tmp_path / "k"
    for name, kind in (("v", "ed25519"), ("u", "x25519")):
        assert (
            r.invoke(
                app, ["keygen", name, "--kind", kind, "--out-dir", str(k)]
            ).exit_code
            == 0
        )
    plain = tmp_path / "p"
    plain.mkdir()
    (plain / "m.jsonl").write_text("{}\n")
    tpl = tmp_path / "t.json"
    tpl.write_text('{"depositor":{"name":"v"},"holder":{"name":"h"}}')
    out = tmp_path / "o"
    res = r.invoke(
        app,
        [
            "deposit",
            "--manifest",
            str(tpl),
            "--artefacts",
            str(plain),
            "--beneficiary-pub",
            str(k / "u.pub"),
            "--depositor-key",
            str(k / "v.key"),
            "--out",
            str(out),
            "--now",
            T0,
        ],
    )
    assert res.exit_code == 0, res.output
    assert (
        r.invoke(app, ["check", str(out / "manifest.json"), "--now", T0]).exit_code == 0
    )
    assert (
        r.invoke(
            app, ["check", str(out / "manifest.json"), "--now", "2027-01-01T00:00:00Z"]
        ).exit_code
        == 3
    )
    (out / "artefacts" / "m.jsonl.x25519").write_bytes(b"junk")
    assert (
        r.invoke(app, ["check", str(out / "manifest.json"), "--now", T0]).exit_code == 4
    )


def test_keys_are_gitignored():
    gi = (Path(__file__).parent.parent / ".gitignore").read_text()
    assert "*.key" in gi


# ---- differential tests: independent implementation using only `cryptography` ----
import sys, hashlib as _hl, struct as _st
from cryptography.hazmat.primitives import hashes as _h, serialization as _ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _XP, X25519PublicKey as _XPub
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _CC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF

_RAW = dict(encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw)


def _ref_kek(priv_or_eph, peer_pub: bytes, eph_pub: bytes, ben_pub: bytes) -> bytes:
    shared = priv_or_eph.exchange(_XPub.from_public_bytes(peer_pub))
    return _HKDF(_h.SHA256(), 32, salt=eph_pub + ben_pub, info=b"aiescrow-v0.1-wrap").derive(shared)


def ref_decrypt(blob: bytes, ben_priv_hex: str) -> bytes:
    priv = _XP.from_private_bytes(bytes.fromhex(ben_priv_hex))
    ben_pub = priv.public_key().public_bytes(**_RAW)
    assert blob[:4] == b"AIE1"
    eph, wn, wrapped, prefix = blob[4:36], blob[36:48], blob[48:96], blob[96:100]
    ck = _CC(_ref_kek(priv, eph, eph, ben_pub)).decrypt(wn, wrapped, b"AIE1")
    pos, i, out = 100, 0, b""
    while pos < len(blob):
        n = _st.unpack(">I", blob[pos:pos + 4])[0]
        ct = blob[pos + 4:pos + 4 + n]
        pos += 4 + n
        final = pos == len(blob)
        out += _CC(ck).decrypt(prefix + _st.pack(">Q", i), ct, _st.pack(">QB", i, int(final)))
        i += 1
    return out


def ref_encrypt(data: bytes, ben_pub_hex: str, chunk: int = 1 << 20) -> bytes:
    import os as _os
    ben = bytes.fromhex(ben_pub_hex)
    eph = _XP.generate()
    eph_pub = eph.public_key().public_bytes(**_RAW)
    ck, wn, prefix = _os.urandom(32), _os.urandom(12), _os.urandom(4)
    wrapped = _CC(_ref_kek(eph, ben, eph_pub, ben)).encrypt(wn, ck, b"AIE1")
    out = b"AIE1" + eph_pub + wn + wrapped + prefix
    parts = [data[j:j + chunk] for j in range(0, len(data), chunk)] or [b""]
    for i, p in enumerate(parts):
        ct = _CC(ck).encrypt(prefix + _st.pack(">Q", i), p, _st.pack(">QB", i, int(i == len(parts) - 1)))
        out += _st.pack(">I", len(ct)) + ct
    return out


@pytest.mark.parametrize("size", [0, 10, 1 << 20, (2 << 20) + 123])
def test_diff_cli_encrypt_reference_decrypt(tmp_path, size):
    r = CliRunner()
    k = tmp_path / "k"
    r.invoke(app, ["keygen", "v", "--kind", "ed25519", "--out-dir", str(k)])
    r.invoke(app, ["keygen", "u", "--kind", "x25519", "--out-dir", str(k)])
    plain = tmp_path / "p"
    plain.mkdir()
    data = os.urandom(size)
    (plain / "f.bin").write_bytes(data)
    tpl = tmp_path / "t.json"
    tpl.write_text('{"depositor":{"name":"v"},"holder":{"name":"h"}}')
    res = r.invoke(app, ["deposit", "--manifest", str(tpl), "--artefacts", str(plain),
                         "--beneficiary-pub", str(k / "u.pub"), "--depositor-key", str(k / "v.key"),
                         "--out", str(tmp_path / "o"), "--now", T0])
    assert res.exit_code == 0, res.output
    blob = (tmp_path / "o" / "artefacts" / "f.bin.x25519").read_bytes()
    assert ref_decrypt(blob, (k / "u.key").read_text().strip()) == data


@pytest.mark.parametrize("size", [0, 77, (1 << 20) + 5])
def test_diff_reference_encrypt_cli_decrypt(tmp_path, size):
    priv, pub = crypto.gen_keypair("x25519")
    data = os.urandom(size)
    (tmp_path / "e").write_bytes(ref_encrypt(data, pub))
    assert crypto.decrypt_file(tmp_path / "e", tmp_path / "d", priv) == _hl.sha256(data).hexdigest()
    assert (tmp_path / "d").read_bytes() == data


def test_standalone_verifier(env):
    script = Path(__file__).parent.parent / "tools" / "verify_manifest.py"
    mp = str(env["out"] / "manifest.json")
    run = lambda: subprocess.run([sys.executable, "-I", str(script), mp], capture_output=True, text=True)
    assert run().returncode == 0
    with open(env["out"] / "artefacts" / "w.bin.x25519", "ab") as f:
        f.write(b"x")
    r = run()
    assert r.returncode == 4 and "FAIL" in r.stdout


def _attest_verify(*args):
    import sys

    v = Path(__file__).parent.parent / "tools" / "attest_verify.py"
    return subprocess.run(
        [sys.executable, str(v), *map(str, args)], capture_output=True, text=True
    ).returncode


def test_manifest_dsse_verifies(env):
    out = env["out"]
    assert (
        _attest_verify(
            out / "manifest.dsse.json",
            "--key",
            out / "depositor.pub.hex",
            "--check-subjects",
            out,
        )
        == 0
    )


def test_manifest_dsse_detects_manifest_change(env):
    out = env["out"]
    with open(out / "manifest.json", "ab") as f:
        f.write(b" ")
    assert (
        _attest_verify(
            out / "manifest.dsse.json",
            "--key",
            out / "depositor.pub.hex",
            "--check-subjects",
            out,
        )
        == 3
    )


def test_attest_verify_copy_identical_to_spec_repo():
    import hashlib

    spec = Path(__file__).parent.parent.parent / "attest-spec" / "attest_verify.py"
    if not spec.exists():
        pytest.skip("attest-spec repo not alongside")
    mine = Path(__file__).parent.parent / "tools" / "attest_verify.py"
    assert hashlib.sha256(mine.read_bytes()).hexdigest() == hashlib.sha256(
        spec.read_bytes()
    ).hexdigest()
