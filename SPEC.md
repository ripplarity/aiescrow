# User-State Escrow v0.1

License: CC-BY-4.0 (this document). Reference code: Apache-2.0.
Status: draft, v0.1. Key words MUST / SHOULD / MAY follow RFC 2119.

## 1. Purpose and terms

Software vendors shut down, get acquired, or deprecate products, and the state users built inside them (fine-tunes, memories, chat histories, configuration, model artefacts) disappears. User-State Escrow is a small standard by which a vendor commits to deposit that state, encrypted to the user, with a neutral party, and to have it released to the user under stated conditions.

- **Artefact**: one file of user state.
- **Escrow**: a directory (or git repository) holding `manifest.json`, `heartbeat.json`, `artefacts/<name>.age`, and later `release.json`.
- **Heartbeat**: a periodically re-signed timestamp proving the vendor is alive (a deadman switch).

## 2. Roles

- **Depositor**: the vendor. Holds an ed25519 signing key. Signs the manifest and heartbeats.
- **Beneficiary**: the user (or a user group). Holds an X25519 key. Only the beneficiary can decrypt.
- **Holder**: a neutral party storing the escrow and signing release records with its own ed25519 key. A holder can be a folder, a git repository, a foundation, or any third party. The holder never sees plaintext or the beneficiary private key.

## 3. Manifest

`manifest.json` MUST validate against `schema/manifest.schema.json`. Fields: `escrow_id, depositor, beneficiary_id_hash, created_at, artefacts[], release_conditions[], holder, signatures[]`.

```json
{
  "escrow_id": "b354dfb9-1e8e-4937-ba73-c32995383d6d",
  "depositor": {"name": "acme", "pubkey": "<ed25519 hex>"},
  "beneficiary_id_hash": "<sha256 of beneficiary X25519 public key>",
  "created_at": "2026-01-01T00:00:00Z",
  "artefacts": [{"name": "memories.jsonl", "kind": "memory", "sha256": "<of encrypted file>",
                 "size": 123, "plaintext_sha256": "<optional>", "encryption": "x25519"}],
  "release_conditions": [{"type": "deadman", "params": {"interval_days": 90, "grace_days": 30}},
                         {"type": "vendor_shutdown"}],
  "holder": {"name": "demo-holder", "type": "git"},
  "signatures": [{"role": "depositor", "pubkey": "<hex>", "sig": "<ed25519 hex>"}]
}
```

Artefact kinds: `model_weights, fine_tune, memory, history, config, other`. Condition types: `vendor_shutdown, acquisition, deprecation, deadman, court_order`. Encryption: `x25519` (the format in section 4) or `age` (reserved name for the stored-file suffix `.age`; v0.1 reference code writes `x25519`).

`sha256` and `size` describe the encrypted file so anyone can verify integrity without a key. The signature is ed25519 over the canonical JSON (sorted keys, separators `,` and `:`, UTF-8) of the manifest without `signatures`. All timestamps are UTC ISO-8601 (`YYYY-MM-DDThh:mm:ssZ`).

## 4. Encryption

Each artefact is encrypted independently. A random 256-bit content key encrypts the file with ChaCha20-Poly1305 in 1 MiB chunks (streaming; implementations MUST NOT load whole files). The content key is wrapped to the beneficiary X25519 key using an ephemeral key, X25519 exchange, and HKDF-SHA256. Nonce is a random 4-byte prefix plus a 64-bit chunk index; AAD binds the chunk index and a final-chunk flag, so truncation, reordering and appending are detected. Byte layout is in `aiescrow/crypto.py`.

## 5. Deposit flow

1. Beneficiary (or the vendor on their behalf) provides an X25519 public key.
2. Vendor encrypts each artefact, computes hashes, signs the manifest.
3. Holder receives manifest, ciphertexts and initial heartbeat. A git holder records each put as a commit, which is the audit log.
4. Vendor publishes the manifest URL (see `badge/BADGE.md`).

Deposits SHOULD be refreshed when state changes materially; each refresh is a new signed manifest.

## 6. Heartbeat (deadman switch)

The vendor re-signs `heartbeat.json` (`escrow_id, timestamp, pubkey, sig`) at least every `interval_days` (default 90). `aiescrow check` exits 3 when the newest valid heartbeat is older than the interval. A heartbeat is evidence that the vendor key is alive; it is not evidence that the product is healthy.

## 7. Release flow

A holder writes `release.json`, signed with the holder key, stating `condition`, `released_at`, `manifest_sha256`, and `holder_attestation`.

- `deadman`: permitted only when the heartbeat is expired. The record carries `contest_until` = last heartbeat + interval + grace (default 30 days). Within the grace period the vendor can contest by resuming heartbeats; beneficiaries MUST NOT be able to open before `contest_until` (the reference `open` refuses).
- `vendor_shutdown` (and `acquisition`, `deprecation`): the holder records an attestation (public notice, registry filing, announcement URL). The reference tool requires non-empty attestation text.
- `court_order`: the holder records the order reference.

If `holder.pubkey` is present in the manifest, `open` rejects release records signed by another key. Decryption is performed locally by the beneficiary with `aiescrow open`.

## 8. Verification

Anyone can run `aiescrow check <manifest>` with no secrets. It verifies manifest schema, depositor signature, every artefact size and sha256, heartbeat signature and age. Exit codes: 0 valid, 3 heartbeat expired, 4 tamper or invalid, 5 release refused (release/open only). After `open`, plaintext hashes are compared to `plaintext_sha256`.

For testing, commands accept `--now <ISO-8601>` to override the clock. This option is TEST-ONLY and MUST NOT be used by production tooling.

## 9. Threat model

- **Holder collusion with vendor**: a holder could withhold or delete. Mitigation: ciphertext hashes are public, so deletion is detectable; use a git or replicated holder; multiple holders are allowed by publishing several escrows.
- **Holder collusion with a third party**: the holder cannot decrypt (no beneficiary key). A leaked ciphertext is useless without that key.
- **Vendor lies about shutdown**: a vendor could claim shutdown to trigger release early, or hide it to avoid release. Deadman release does not depend on vendor honesty; shutdown release depends on holder attestation and is only as strong as the holder.
- **Vendor deposits junk**: the standard proves integrity, not usefulness. Beneficiaries SHOULD test-open a deposit at least once.
- **Key loss**: if the beneficiary loses the X25519 key, nothing can be recovered. Recovery is out of scope for v0.1; social recovery (Shamir shares among trusted parties) is recommended. `open` fails with a clear error.
- **Vendor key compromise**: an attacker can forge heartbeats and keep release from triggering. Publish the depositor key in an independent place and rotate it by issuing a new manifest.
- **Clock skew**: all timestamps are UTC; verifiers compare against their own clock; grace periods absorb skew.

## 10. What this standard does NOT promise

- No guarantee the vendor deposits everything, or deposits it on time.
- No legal enforceability; it is a technical commitment, not a contract.
- No protection against a malicious or negligent holder beyond detectability.
- No key recovery, no revocation of past releases, no format migration of the artefacts.
- No confidentiality against the vendor, who already holds the plaintext.
- No post-quantum security (X25519, ed25519).
