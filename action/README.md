# aiescrow release action

Deposits your users' state into a git branch `escrow` on each release, so the badge in `badge/BADGE.md` is backed by a passing check.

1. Generate keys: `aiescrow keygen vendor`, `aiescrow keygen holder`; each user (or a community key) runs `aiescrow keygen user --kind x25519`.
2. Store `vendor.key` as the repository secret `ESCROW_DEPOSITOR_KEY`. Never commit it.
3. Publish `aiescrow keyid vendor.pub` in your README (out of band) and use it as `expect_keyid`.
4. Add a workflow on `release: published` with `actions/checkout` (`fetch-depth: 0`) and `permissions: contents: write`.
5. Call `uses: <owner>/aiescrow/action@<ref>` with `artefacts`, `beneficiary_pub`, `depositor_key: ${{ secrets.ESCROW_DEPOSITOR_KEY }}`, `holder_pub`, `expect_keyid`.
6. Artefacts are encrypted to the beneficiary key; the holder branch only ever holds ciphertext, the signed manifest and the heartbeat.
7. The step fails unless `aiescrow check` passes; link the badge to the manifest URL on the `escrow` branch.
8. Same repo means a self-held escrow: it protects against loss, not against you disappearing; say so next to the badge.
9. Re-run on a schedule (cron) at least every 90 days to keep the heartbeat fresh.
10. Try it offline first: `bash action/simulate.sh` (prints CHECK OK).
