#!/usr/bin/env bash
# End-to-end demo. --now is a TEST-ONLY clock override used to simulate time passing.
set -euo pipefail
export AIESCROW_TEST_CLOCK=1   # required for the test-only --now override
cd "$(dirname "$0")/.."
PY="${PYTHON:-python}"
A="$PY -m aiescrow"
O=examples/out
rm -rf "$O"; mkdir -p "$O/plain" "$O/keys"

# a tiny fake fine-tune (1 MB random) and a memories file
head -c 1048576 /dev/urandom > "$O/plain/adapter.safetensors"
printf '{"role":"user","text":"remember my cat is called Miso"}\n' > "$O/plain/memories.jsonl"

$A keygen vendor --kind ed25519 --out-dir "$O/keys"
$A keygen holder --kind ed25519 --out-dir "$O/keys"
$A keygen user   --kind x25519  --out-dir "$O/keys"

HPUB=$(cat "$O/keys/holder.pub")
KID=$($PY -m aiescrow keyid "$O/keys/vendor.pub")   # trusted pin, obtained out of band
cat > "$O/template.json" <<EOF
{"depositor":{"name":"ollama-finetune-demo"},
 "holder":{"name":"demo-holder","type":"local","pubkey":"$HPUB"},
 "artefact_kinds":{"adapter.safetensors":"fine_tune","memories.jsonl":"memory"},
 "release_conditions":[{"type":"deadman","params":{"interval_days":90,"grace_days":30}},
                       {"type":"vendor_shutdown"}]}
EOF

$A deposit --manifest "$O/template.json" --artefacts "$O/plain" \
  --beneficiary-pub "$O/keys/user.pub" --depositor-key "$O/keys/vendor.key" \
  --out "$O" --now 2026-01-01T00:00:00Z
$A heartbeat --dir "$O" --depositor-key "$O/keys/vendor.key" --now 2026-02-01T00:00:00Z
$A check "$O/manifest.json" --expect-keyid "$KID" --now 2026-03-01T00:00:00Z

# vendor goes silent; deadman after 90 days + 30 days grace
$A release --dir "$O" --condition deadman --holder-key "$O/keys/holder.key" --expect-keyid "$KID" --now 2026-06-01T00:00:00Z
$A open --dir "$O" --key "$O/keys/user.key" --out "$O/restored" --expect-keyid "$KID" --now 2026-07-01T00:00:00Z

# independent hash comparison
for f in adapter.safetensors memories.jsonl; do
  a=$(sha256sum "$O/plain/$f" | cut -d' ' -f1); b=$(sha256sum "$O/restored/$f" | cut -d' ' -f1)
  [ "$a" = "$b" ] || { echo "HASH MISMATCH $f"; exit 1; }
done
echo "HASH OK (independent sha256sum)"

# vendor resumes: a real-clock heartbeat so `aiescrow check` passes without --now
$A heartbeat --dir "$O" --depositor-key "$O/keys/vendor.key"
