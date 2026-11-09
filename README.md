<p align="center">
  <img src="assets/logo.svg" width="112" alt="aiescrow logo: a vault with a dial">
</p>

<h1 align="center">aiescrow: escrow for user state</h1>

<p align="center">
  <b>If an AI product shuts down, its users' state should not die with it.</b><br>
  A standard and reference CLI that deposit users' fine-tunes, memories and histories, encrypted to the users, with an independent holder and a dead-man release.
</p>

<p align="center">
  <img src="assets/badges.svg" alt="User-State Escrow v0.1 · encrypted deposits · spec CC-BY-4.0 · code Apache-2.0">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> · <a href="#how-it-works">How it works</a> · <a href="#trust-model">Trust model</a> · <a href="#faq">FAQ</a>
</p>

<p align="center"><code>bash examples/run_demo.sh</code></p>

---

## Why

Users invest months in an AI product's memory of them. When the vendor shuts down, that state usually goes too. User-State Escrow lets a vendor deposit it, encrypted to the users, with a holder the vendor does not control alone, and lets anyone check that the deposit is current.

## Quick start

```bash
uv venv .venv && uv pip install -e ".[dev]" && python -m pytest -q
bash examples/run_demo.sh            # or examples/run_demo.ps1 on Windows
```

Adopting it in your product: [`docs/ADOPT.md`](docs/ADOPT.md). A GitHub Action that deposits on each release: [`action/README.md`](action/README.md).

## How it works

| Step | Command |
|---|---|
| Keys | `aiescrow keygen vendor` (ed25519), `keygen holder`, each user `keygen user --kind x25519` |
| Deposit | `aiescrow deposit --manifest template.json --artefacts ./export --beneficiary-pub user.pub --depositor-key vendor.key --out ./escrow` |
| Heartbeat | `aiescrow heartbeat` at least every 90 days |
| Check | `aiescrow check manifest.json --expect-keyid <vendor keyid>` (0 valid, 2 usage, 3 heartbeat expired, 4 tamper) |
| Release | after the dead-man condition, `release` and `open` |

## Before you cancel: verify your export

Official exports can silently omit items, and access can end on cancel or downgrade. Check an export (directory or zip with `conversations*.json`, optional `memories/` and `attachments/`) against an expected manifest such as `{"conversations": {"count": 3, "ids": ["c1","c2","c3"]}, "memories": 2}`:

```bash
aiescrow verify-export ./export.zip --expected expected.json          # 0 complete, 6 incomplete
aiescrow verify-export ./export --expected expected.json --snapshot ./snap1 \
  --beneficiary-pub user.pub --depositor-key me.key --expect-keyid <my keyid>
aiescrow snapshot-diff ./snap1 ./snap2 --expect-keyid <my keyid>      # 6 if items disappeared
```

A snapshot is a normal escrow deposit (signed manifest, `check`-able), plus a plaintext copy whose hashes are bound to the signed inventory. Exit 4 means a snapshot was altered. `snapshot-diff` exits 2 ("snapshot order") unless NEW was signed strictly after OLD, so an older snapshot passed as NEW cannot read as no loss.

Limits: only items with an `id` count toward a conversation count; an empty manifest or an unknown kind is exit 2. Names are NFC-normalised on both sides before matching. A case-insensitive filesystem (Windows, default macOS) can collapse ids that differ only by case: UNTESTED. Memories are identified by file stem, so two files with the same stem in different subfolders count once. Zips are refused (exit 2) above 100,000 members or 8 GiB uncompressed (2 GiB per member), checked before and during extraction.

## Trust model

- Artefacts are encrypted to the beneficiary key; the holder only ever stores ciphertext, the signed manifest and the heartbeat.
- `check`, `release` and `open` REQUIRE `--expect-keyid`. A key found beside the artefact is untrusted unless it matches the pin, and every signature must verify under it.
- `holder.pubkey` is required in the manifest, and `release`/`open` always verify the holder signature.
- Manifests are signed in the [attest-spec](https://github.com/ripplarity/attest-spec) format (`manifest.dsse.json`).

## Limits

- A holder you control yourself (for example the same repository) protects against loss, not against you disappearing. Say so next to the badge.
- The badge shows that the last check passed. It is not independent custody unless the holder is independent.
- No Ripplarity keyid is published yet; vendors publish their own (`aiescrow keyid vendor.pub`).

## FAQ

**What counts as user state?** Whatever is worth protecting: fine-tunes, memories, histories, configs, model artefacts.

**Can the holder read the data?** No. It is encrypted to the users' keys.

**What happens if the vendor stops sending heartbeats?** After the deadline, `check` reports the expired heartbeat (exit 3) and the release conditions apply.

**Is there a badge?** Yes, see [`badge/BADGE.md`](badge/BADGE.md). Link it to your published manifest.

---

<p align="center"><sub>Standard CC-BY-4.0 (<code>LICENSE-SPEC</code>) · code Apache-2.0 (<code>LICENSE</code>) · Ripplarity Inc.</sub></p>
