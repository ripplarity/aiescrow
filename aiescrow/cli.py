"""aiescrow CLI. NOTE: --now is a TEST-ONLY clock override."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from . import core, crypto

app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="User-State Escrow v0.1"
)
NOW = typer.Option(None, "--now", help="TEST ONLY: override the UTC clock (ISO-8601).")


def _run(fn):
    try:
        return fn()
    except core.EscrowError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(e.code)


@app.command()
def keygen(
    name: str,
    kind: str = typer.Option(
        "ed25519", help="ed25519 (signing) or x25519 (beneficiary)"
    ),
    out_dir: Path = Path("."),
):
    """Write NAME.key (private, keep secret) and NAME.pub."""
    if kind not in ("ed25519", "x25519"):
        raise typer.BadParameter("kind must be ed25519 or x25519")
    priv, pub = crypto.gen_keypair(kind)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.key").write_text(priv + "\n")
    (out_dir / f"{name}.pub").write_text(pub + "\n")
    typer.echo(f"wrote {out_dir / (name + '.key')} and {out_dir / (name + '.pub')}")


@app.command()
def deposit(
    manifest: Path = typer.Option(..., help="manifest template JSON"),
    artefacts: Path = typer.Option(..., help="directory of plaintext artefacts"),
    beneficiary_pub: str = typer.Option(..., help="X25519 public key (hex or file)"),
    depositor_key: str = typer.Option(..., help="ed25519 private key (hex or file)"),
    out: Path = typer.Option(..., help="holder directory"),
    git: bool = typer.Option(False, help="use git holder"),
    now: str | None = NOW,
):
    """Encrypt artefacts, sign the manifest, hand to the holder."""
    m = _run(
        lambda: core.deposit(
            json.loads(manifest.read_text()),
            artefacts,
            core.read_key(beneficiary_pub),
            core.read_key(depositor_key),
            out,
            now,
            git,
        )
    )
    typer.echo(f"DEPOSITED {m['escrow_id']} ({len(m['artefacts'])} artefacts)")


@app.command()
def heartbeat(
    dir: Path = typer.Option(..., help="holder directory"),
    depositor_key: str = typer.Option(...),
    git: bool = False,
    now: str | None = NOW,
):
    """Re-sign heartbeat.json with the current UTC time."""
    hb = _run(lambda: core.heartbeat(dir, core.read_key(depositor_key), now, git))
    typer.echo(f"HEARTBEAT {hb['timestamp']}")


@app.command()
def check(manifest: Path, now: str | None = NOW):
    """Exit 0 valid, 3 heartbeat expired, 4 tamper."""
    s = _run(lambda: core.check(manifest, now))
    typer.echo(
        f"OK {s['escrow_id']} artefacts={s['artefacts']} heartbeat_age_days={s['heartbeat_age_days']}"
    )


@app.command()
def release(
    dir: Path = typer.Option(...),
    condition: str = typer.Option(..., help="deadman|shutdown"),
    holder_key: str = typer.Option(...),
    attestation: str = "",
    git: bool = False,
    now: str | None = NOW,
):
    """Write a holder-signed release record."""
    r = _run(
        lambda: core.release(
            dir, condition, core.read_key(holder_key), now, attestation, git
        )
    )
    typer.echo(f"RELEASED condition={r['condition']} at={r['released_at']}")


@app.command(name="open")
def open_(
    dir: Path = typer.Option(...),
    key: str = typer.Option(..., help="beneficiary X25519 private key"),
    out: Path = typer.Option(...),
    now: str | None = NOW,
):
    """Decrypt released artefacts (beneficiary)."""

    def go():
        k = core.read_key(key)
        return core.open_release(dir, k, out, now)

    res = _run(go)
    for r in res:
        typer.echo(f"{r['name']} {r['sha256']}")
    typer.echo("HASH OK")


if __name__ == "__main__":
    app()
