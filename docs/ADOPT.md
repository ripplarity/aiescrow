# Adopting User-State Escrow (small SaaS or OSS maintainer)

1. Decide what user state is worth protecting: fine-tunes, memories, histories, configs, model artefacts.
2. Install from a checkout: `uv venv .venv && uv pip install -e .`. Python 3.12+.
3. Generate your signing key: `aiescrow keygen vendor --kind ed25519`. Store `vendor.key` in a secrets manager. Never commit it (`*.key` is gitignored in this repo; do the same in yours).
4. Get the beneficiary public key: each user (or a community key held by a user group) runs `aiescrow keygen user --kind x25519` and gives you `user.pub`. They keep `user.key`; consider splitting it among trusted people, since key loss is unrecoverable.
5. Pick a holder: a separate git repository you do not control alone (foundation, partner, a trusted maintainer), or a folder on independent storage. Generate the holder's signing key with `keygen`.
6. Write a template JSON with your name, the holder's name and public key (`holder.pubkey`, required), `artefact_kinds`, and release conditions (at least `deadman`; add `vendor_shutdown`).
7. Deposit: `aiescrow deposit --manifest template.json --artefacts ./export --beneficiary-pub user.pub --depositor-key vendor.key --out ./escrow [--git]`.
8. Schedule `aiescrow heartbeat --dir ./escrow --depositor-key vendor.key` at least every 90 days (cron or CI), and re-deposit when state changes.
9. Publish `manifest.json`, `heartbeat.json` and `artefacts/` at a stable URL, and add the badge per `badge/BADGE.md` linking the manifest URL.
10. Test-open once: print your keyid (`aiescrow keyid vendor.pub`), simulate a lapse with `--now` (test-only; needs env `AIESCROW_TEST_CLOCK=1`), run `release` and `open` with `--expect-keyid <your keyid>`, and confirm `HASH OK`.

How users verify: download the published files and run `aiescrow check manifest.json --expect-keyid <vendor keyid>` (0 valid, 2 usage, 3 heartbeat expired, 4 tamper); the vendor publishes its keyid out of band. They need no secrets. To receive their data after a release, run `aiescrow open --dir <escrow> --key user.key --out ./restored --expect-keyid <vendor keyid>`.

What to publish: manifest, heartbeat, encrypted artefacts, the holder name and public key, and the contest period. Never publish private keys.
