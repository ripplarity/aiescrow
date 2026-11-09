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
