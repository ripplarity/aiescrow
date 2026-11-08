# aiescrow

User-State Escrow v0.1: a standard (`SPEC.md`, CC-BY-4.0) and reference implementation (Apache-2.0) so a vendor's shutdown does not destroy user state. See `docs/ADOPT.md`, `badge/BADGE.md`, and `examples/run_demo.sh`.

    uv venv .venv && uv pip install -e ".[dev]" && python -m pytest -q

## Attestations (attest-spec v1)

`deposit` also writes `manifest.dsse.json` (DSSE + in-toto Statement v1) and `depositor.pub.hex` beside `manifest.json`. Verify: `python tools/attest_verify.py manifest.dsse.json --key depositor.pub.hex --check-subjects .`. Hex keys stay internal; keyid is sha256 of the raw public key.

## Key pinning and trust

`check`, `release` and `open` REQUIRE `--expect-keyid <hex>` (sha256 of the raw depositor ed25519 public key). A key found beside the artefact (`depositor.pub.hex`, or the one inside `manifest.json`) is untrusted unless it matches the pin; every `signatures[]` entry must verify under the pinned keyid or `check` exits 4. Your keyid is generated per install: run `python -m aiescrow keyid vendor.pub`, then publish it in this README (replace the placeholder), in `https://ripplarity.com/.well-known/attestation-keys.json` (a founder action) and in the key's first transparency-log entry.

    producer keyid (aiescrow): <PUBLISH YOURS HERE - per-install, from `aiescrow keyid`>

`holder.pubkey` is required in the manifest and `release`/`open` always verify the holder signature against it. `--now` works only with env `AIESCROW_TEST_CLOCK=1` (tests/demo); otherwise it exits 2. JSON with duplicate keys is rejected. `tools/verify_manifest.py MANIFEST --expect-keyid HEX` is the standalone check.
