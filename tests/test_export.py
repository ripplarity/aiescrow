import json
import shutil
import zipfile

import pytest
from aiescrow import core, crypto
from aiescrow.cli import app
from typer.testing import CliRunner

R = CliRunner()
FULL = {
    "conversations": {"count": 3, "ids": ["c1", "c2", "c3"]},
    "memories": 2,
    "attachments": 1,
}


@pytest.fixture(autouse=True)
def _clk(monkeypatch):
    monkeypatch.setenv("AIESCROW_TEST_CLOCK", "1")


def mk(root, convs=("c1", "c2", "c3"), mems=("m1", "m2"), atts=("a.png",)):
    root.mkdir(parents=True)
    (root / "conversations.json").write_text(json.dumps([{"id": c} for c in convs]))
    (root / "memories").mkdir()
    for m in mems:
        (root / "memories" / f"{m}.json").write_text("{}")
    (root / "attachments").mkdir()
    for a in atts:
        (root / "attachments" / a).write_bytes(b"x" + a.encode())
    return root


def exp(p, d):
    p.write_text(json.dumps(d))
    return str(p)


def keys():
    vp, vpub = crypto.gen_keypair("ed25519")
    _, bpub = crypto.gen_keypair("x25519")
    return vp, bpub, core.keyid_of(vpub)


def test_complete_dir_and_zip(tmp_path):
    e = mk(tmp_path / "e")
    x = exp(tmp_path / "x.json", FULL)
    r = R.invoke(app, ["verify-export", str(e), "--expected", x])
    assert r.exit_code == 0 and "COMPLETE" in r.output
    z = tmp_path / "e.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for f in e.rglob("*"):
            if f.is_file():
                zf.write(f, "exp/" + f.relative_to(e).as_posix())
    assert R.invoke(app, ["verify-export", str(z), "--expected", x]).exit_code == 0


def test_missing_items_exit_6(tmp_path):
    e = mk(tmp_path / "e", convs=("c1", "c3"), mems=("m1",))
    r = R.invoke(
        app, ["verify-export", str(e), "--expected", exp(tmp_path / "x.json", FULL)]
    )
    assert r.exit_code == 6
    assert "conversations: expected=3 found=2 missing=1 ids=c2" in r.output
    assert "memories: expected=2 found=1 missing=1" in r.output


def snap(tmp_path, name, e, vp, bpub, kid, now="2026-11-01T00:00:00Z"):
    s = tmp_path / name
    r = R.invoke(
        app,
        [
            "verify-export",
            str(e),
            "--expected",
            exp(tmp_path / "x.json", FULL),
            "--snapshot",
            str(s),
            "--beneficiary-pub",
            bpub,
            "--depositor-key",
            vp,
            "--expect-keyid",
            kid,
            "--now",
            now,
        ],
    )
    return s, r


def test_snapshot_and_disappeared(tmp_path):
    vp, bpub, kid = keys()
    s1, r = snap(tmp_path, "s1", mk(tmp_path / "e1"), vp, bpub, kid)
    assert r.exit_code == 0 and "SNAPSHOT OK" in r.output
    assert (
        R.invoke(
            app, ["check", str(s1 / "manifest.json"), "--expect-keyid", kid]
        ).exit_code
        == 0
    )
    s2, r = snap(
        tmp_path, "s2", mk(tmp_path / "e2", convs=("c1", "c3")), vp, bpub, kid,
        now="2026-11-02T00:00:00Z",
    )
    assert r.exit_code == 6  # snapshot written, export incomplete
    d = R.invoke(app, ["snapshot-diff", str(s1), str(s2), "--expect-keyid", kid])
    assert d.exit_code == 6 and "conversations: disappeared 1: c2" in d.output
    assert (
        R.invoke(
            app, ["snapshot-diff", str(s1), str(s1), "--expect-keyid", kid]
        ).exit_code
        == 2  # R1: the same snapshot is not strictly later than itself
    )


def test_tampered_snapshot_fails(tmp_path):
    vp, bpub, kid = keys()
    s1, _ = snap(tmp_path, "s1", mk(tmp_path / "e1"), vp, bpub, kid)
    s2, _ = snap(tmp_path, "s2", mk(tmp_path / "e2"), vp, bpub, kid, now="2026-11-02T00:00:00Z")
    s3 = tmp_path / "s3"
    shutil.copytree(s1, s3)
    _, _, other = keys()
    assert (
        R.invoke(
            app, ["snapshot-diff", str(s3), str(s3), "--expect-keyid", other]
        ).exit_code
        == 4
    )
    (s1 / "export" / "memories" / "m1.json").write_text('{"x":1}')
    assert (
        R.invoke(
            app, ["snapshot-diff", str(s1), str(s2), "--expect-keyid", kid]
        ).exit_code
        == 4
    )
    a = s2 / "artefacts" / "inventory.json.x25519"
    a.write_bytes(a.read_bytes() + b"0")
    assert (
        R.invoke(
            app, ["check", str(s2 / "manifest.json"), "--expect-keyid", kid]
        ).exit_code
        == 4
    )


# --- adversarial regressions (one per finding) ---


def _ve(path, expected, tmp_path):
    return R.invoke(app, ["verify-export", str(path), "--expected", exp(tmp_path / "x.json", expected)])


def test_a1_placeholders_never_satisfy_a_count(tmp_path):
    e = tmp_path / "e"
    e.mkdir()
    (e / "conversations.json").write_text(json.dumps([{}, {}, "junk"]))
    r = _ve(e, {"conversations": 3}, tmp_path)
    assert r.exit_code == 6 and "found=0" in r.output


def test_a2_empty_or_unknown_expected_is_usage_error(tmp_path):
    e = tmp_path / "e"
    e.mkdir()
    assert _ve(e, {}, tmp_path).exit_code == 2
    assert _ve(e, {"conversation": 0}, tmp_path).exit_code == 2


def test_a3_zip_with_only_a_kind_folder_is_not_unwrapped(tmp_path):
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("attachments/a.txt", "x")
    r = _ve(z, {"attachments": {"ids": ["a.txt"]}}, tmp_path)
    assert r.exit_code == 0, r.output


def test_a4_zip_bomb_is_refused_before_full_extract(tmp_path, monkeypatch):
    from aiescrow import export

    monkeypatch.setattr(export, "MAX_TOTAL_BYTES", 1024 * 1024)
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        f.writestr("attachments/big.bin", b"\0" * (4 * 1024 * 1024))
    assert _ve(z, {"attachments": 1}, tmp_path).exit_code == 2


def test_a4_lying_member_size_is_capped(tmp_path, monkeypatch):
    from aiescrow import export

    monkeypatch.setattr(export, "MAX_MEMBER_BYTES", 1024)
    z = tmp_path / "lie.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        f.writestr("attachments/big.bin", b"\0" * 8192)
    assert _ve(z, {"attachments": 1}, tmp_path).exit_code == 2


def test_n1_nfc_and_nfd_names_match(tmp_path):
    e = tmp_path / "e"
    (e / "attachments").mkdir(parents=True)
    (e / "attachments" / "cafe\u0301.txt").write_text("x")
    r = _ve(e, {"attachments": {"ids": ["caf\u00e9.txt"]}}, tmp_path)
    assert r.exit_code == 0, r.output


def test_r1_replayed_older_snapshot_as_new_is_refused(tmp_path):
    vp, bpub, kid = keys()
    old, _ = snap(tmp_path, "old", mk(tmp_path / "e1"), vp, bpub, kid, now="2026-11-01T00:00:00Z")
    new, _ = snap(tmp_path, "new", mk(tmp_path / "e2"), vp, bpub, kid, now="2026-11-02T00:00:00Z")
    d = R.invoke(app, ["snapshot-diff", str(new), str(old), "--expect-keyid", kid])
    assert d.exit_code == 2 and "snapshot order" in d.output
    assert R.invoke(app, ["snapshot-diff", str(old), str(new), "--expect-keyid", kid]).exit_code == 0


def test_a4_insufficient_disk_is_refused(tmp_path, monkeypatch):
    import collections

    from aiescrow import export

    du = collections.namedtuple("du", "total used free")
    monkeypatch.setattr(export.shutil, "disk_usage", lambda p: du(10, 10, 512 * 1024**2))
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("attachments/a.txt", "x")
    r = _ve(z, {"attachments": 1}, tmp_path)
    assert r.exit_code == 2 and "insufficient disk" in r.output
