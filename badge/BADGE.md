# Using the User-State Escrow badge

Rules:

1. You MAY show `escrow-v0.1.svg` only if `aiescrow check <your public manifest>` currently exits 0.
2. The badge MUST link to the public URL of your `manifest.json` (not to this repository).
3. Keep heartbeats fresh. If `check` exits 3 or 4, remove the badge until it passes again.
4. Do not alter the text or colours of the mark. Do not imply that anyone endorses or audits your project; the badge only says that the check passes.

Markdown:

```
[![User-State Escrow v0.1](escrow-v0.1.svg)](https://example.com/escrow/manifest.json)
```

HTML:

```
<a href="https://example.com/escrow/manifest.json"><img src="escrow-v0.1.svg" alt="User-State Escrow v0.1"></a>
```

Anyone can verify the claim: download the manifest and the `artefacts/` and `heartbeat.json` beside it, then run `aiescrow check manifest.json`.
