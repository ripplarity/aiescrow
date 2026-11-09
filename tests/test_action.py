import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "action" / "escrow.sh"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="bash required")


def _aie(*a, cwd):
    return subprocess.run([sys.executable, "-m", "aiescrow", *a], cwd=cwd, capture_output=True, text=True, check=True).stdout


@pytest.fixture
def sim(tmp_path):
    k = tmp_path / "k"
    for n, kind in (("vendor", "ed25519"), ("holder", "ed25519"), ("user", "x25519")):
        _aie("keygen", n, "--kind", kind, "--out-dir", str(k), cwd=tmp_path)
    repo = tmp_path / "repo"
    (repo / "state").mkdir(parents=True)
    (repo / "state" / "m.json").write_text('{"a":1}\n')
    g = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@localhost", *a], cwd=repo, check=True, capture_output=True, text=True)  # noqa: E731
    g("init", "-q")
    g("commit", "-q", "--allow-empty", "-m", "init")
    env = {
        **os.environ,
        "ESCROW_ARTEFACTS": "state/*.json",
        "ESCROW_BENEFICIARY_PUB": (k / "user.pub").read_text().strip(),
        "ESCROW_DEPOSITOR_KEY": (k / "vendor.key").read_text().strip(),
        "ESCROW_HOLDER_PUB": (k / "holder.pub").read_text().strip(),
        "ESCROW_EXPECT_KEYID": _aie("keyid", str(k / "vendor.pub"), cwd=tmp_path).strip(),
        "PYTHON": sys.executable,
    }
    return repo, env, g


def run(repo, env):
    return subprocess.run([BASH, str(SH)], cwd=repo, env=env, capture_output=True, text=True)


def test_simulate_script_prints_check_ok():
    r = subprocess.run([BASH, str(ROOT / "action" / "simulate.sh")], env={**os.environ, "PYTHON": sys.executable}, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "CHECK OK" in r.stdout


def test_creates_escrow_branch_with_ciphertext_only(sim):
    repo, env, g = sim
    r = run(repo, env)
    assert r.returncode == 0 and "CHECK OK" in r.stdout, r.stderr
    files = g("ls-tree", "-r", "--name-only", "escrow").stdout.split()
    assert "manifest.json" in files and "heartbeat.json" in files
    assert "artefacts/m.json.x25519" in files and "state/m.json" not in files
    assert g("rev-parse", "--abbrev-ref", "HEAD").stdout.strip() != "escrow"  # working checkout untouched


def test_second_release_reuses_branch(sim):
    repo, env, g = sim
    assert run(repo, env).returncode == 0
    n1 = len(g("log", "--format=%s", "escrow").stdout.split("\n"))
    (repo / "state" / "m.json").write_text('{"a":2}\n')
    r = run(repo, env)
    assert r.returncode == 0 and "CHECK OK" in r.stdout, r.stderr
    assert len(g("log", "--format=%s", "escrow").stdout.split("\n")) > n1
    assert not (Path(repo) / "manifest.json").exists()


def test_wrong_keyid_fails_check(sim):
    repo, env, _ = sim
    r = run(repo, {**env, "ESCROW_EXPECT_KEYID": "0" * 64})
    assert r.returncode != 0 and "CHECK OK" not in r.stdout


def test_no_matching_artefacts_exit_2(sim):
    repo, env, _ = sim
    r = run(repo, {**env, "ESCROW_ARTEFACTS": "nothing/*.zzz"})
    assert r.returncode == 2


def test_private_key_not_committed_to_branch(sim):
    repo, env, _ = sim
    assert run(repo, env).returncode == 0
    r = subprocess.run(["git", "grep", "-I", "-q", env["ESCROW_DEPOSITOR_KEY"], "escrow"], cwd=repo)
    assert r.returncode == 1  # no match
