#!/usr/bin/env bash
# Local simulation of the GitHub Action: scratch git repo, throwaway keys, no network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in "$HERE/.venv/Scripts/python" "$HERE/.venv/bin/python" python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import aiescrow, typer' 2>/dev/null; then PY="$c"; break; fi
  done
fi
[ -n "$PY" ] || { echo "error: no python with aiescrow installed (uv pip install -e .)" >&2; exit 2; }
S="$(mktemp -d)"; trap 'rm -rf "$S"' EXIT
$PY -m aiescrow keygen vendor --kind ed25519 --out-dir "$S/k" >/dev/null
$PY -m aiescrow keygen holder --kind ed25519 --out-dir "$S/k" >/dev/null
$PY -m aiescrow keygen user --kind x25519 --out-dir "$S/k" >/dev/null
mkdir "$S/repo"; cd "$S/repo"
git init -q; git -c user.name=t -c user.email=t@localhost commit -q --allow-empty -m init
mkdir state; printf '{"memory":"simulated"}\n' > state/memories.json
export ESCROW_ARTEFACTS='state/*.json'
export ESCROW_BENEFICIARY_PUB="$(cat "$S/k/user.pub")"
export ESCROW_DEPOSITOR_KEY="$(cat "$S/k/vendor.key")"
export ESCROW_HOLDER_PUB="$(cat "$S/k/holder.pub")"
export ESCROW_EXPECT_KEYID="$($PY -m aiescrow keyid "$S/k/vendor.pub")"
export ESCROW_PUSH=0 PYTHON="$PY"
bash "$HERE/action/escrow.sh"
git rev-parse --verify -q refs/heads/escrow >/dev/null && echo "branch escrow: $(git log --format=%s escrow | wc -l) commits"
