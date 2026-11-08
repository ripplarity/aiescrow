# aiescrow

User-State Escrow v0.1: a standard (`SPEC.md`, CC-BY-4.0) and reference implementation (Apache-2.0) so a vendor's shutdown does not destroy user state. See `docs/ADOPT.md`, `badge/BADGE.md`, and `examples/run_demo.sh`.

    uv venv .venv && uv pip install -e ".[dev]" && python -m pytest -q

## Attestations (attest-spec v1)

`deposit` also writes `manifest.dsse.json` (DSSE + in-toto Statement v1) and `depositor.pub.hex` beside `manifest.json`. Verify: `python tools/attest_verify.py manifest.dsse.json --key depositor.pub.hex --check-subjects .`. Hex keys stay internal; keyid is sha256 of the raw public key.
