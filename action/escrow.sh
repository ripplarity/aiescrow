#!/usr/bin/env bash
# Shared by action.yml and simulate.sh: deposit artefacts to a git branch `escrow`,
# heartbeat, then `aiescrow check`. Run from inside the project's git checkout.
# env: ESCROW_ARTEFACTS (glob) ESCROW_BENEFICIARY_PUB ESCROW_DEPOSITOR_KEY ESCROW_HOLDER_PUB
#      ESCROW_EXPECT_KEYID  [ESCROW_PUSH=0|1] [ESCROW_NAME] [PYTHON]
set -euo pipefail
: "${ESCROW_ARTEFACTS:?artefacts glob required}" "${ESCROW_BENEFICIARY_PUB:?}" \
  "${ESCROW_DEPOSITOR_KEY:?}" "${ESCROW_HOLDER_PUB:?}" "${ESCROW_EXPECT_KEYID:?}"
PY="${PYTHON:-python}"
A="$PY -m aiescrow"
NAME="${ESCROW_NAME:-$(basename "$(git rev-parse --show-toplevel)")}"
T="$(mktemp -d)"
WT="$T/holder"
cleanup() { git worktree remove --force "$WT" >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT

# 1. stage the artefacts matched by the glob (flat directory)
mkdir "$T/plain"
shopt -s globstar nullglob
n=0
for f in $ESCROW_ARTEFACTS; do
  [ -f "$f" ] || continue
  cp "$f" "$T/plain/$(basename "$f")"; n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "error: no files match '$ESCROW_ARTEFACTS'" >&2; exit 2; }

# 2. keys go to private temp files, never onto a command line
umask 077
printf '%s\n' "$ESCROW_DEPOSITOR_KEY" > "$T/depositor.key"
printf '%s\n' "$ESCROW_BENEFICIARY_PUB" > "$T/beneficiary.pub"

# 3. holder = worktree on branch `escrow` (existing, from origin, or a new orphan)
if git rev-parse --verify -q refs/heads/escrow >/dev/null; then
  git worktree add -q "$WT" escrow
elif git rev-parse --verify -q refs/remotes/origin/escrow >/dev/null; then
  git worktree add -q -b escrow "$WT" origin/escrow
else
  git worktree add -q --detach "$WT"
  git -C "$WT" checkout -q --orphan escrow
  git -C "$WT" rm -rq --cached . >/dev/null 2>&1 || true
  find "$WT" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
fi

cat > "$T/template.json" <<JSON
{"depositor":{"name":"$NAME"},
 "holder":{"name":"escrow branch of $NAME","type":"git","pubkey":"$ESCROW_HOLDER_PUB"},
 "release_conditions":[{"type":"deadman","params":{"interval_days":90,"grace_days":30}}]}
JSON

# 4. deposit, heartbeat, check
$A deposit --manifest "$T/template.json" --artefacts "$T/plain" \
  --beneficiary-pub "$T/beneficiary.pub" --depositor-key "$T/depositor.key" --out "$WT" --git
$A heartbeat --dir "$WT" --depositor-key "$T/depositor.key" --git
$A check "$WT/manifest.json" --expect-keyid "$ESCROW_EXPECT_KEYID"
echo "CHECK OK"

if [ "${ESCROW_PUSH:-0}" = "1" ]; then git push origin escrow; fi
