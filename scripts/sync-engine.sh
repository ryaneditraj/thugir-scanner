#!/usr/bin/env bash
# Sync thugir-node (TCSF) from github.com/ryaneditraj/thugirlabs.com into ./engine
# so Deep Scan can import tcsf.* / nexus.* without a monorepo checkout.
#
# Usage:
#   ./scripts/sync-engine.sh              # tip of main
#   ./scripts/sync-engine.sh <git-ref>    # branch / tag / sha
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE="$ROOT/engine"
REF="${1:-main}"
REPO="${THUGIRLABS_REPO:-https://github.com/ryaneditraj/thugirlabs.com.git}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/thugir-engine.XXXXXX")"

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "→ Sparse-cloning thugir-node from thugirlabs.com @ $REF …"
git clone --filter=blob:none --sparse --depth 1 --branch "$REF" "$REPO" "$TMP/repo" \
  || git clone --filter=blob:none --sparse --depth 1 "$REPO" "$TMP/repo" \
  && git -C "$TMP/repo" checkout "$REF"

git -C "$TMP/repo" sparse-checkout set thugir-node

if [[ ! -d "$TMP/repo/thugir-node/tcsf" ]]; then
  echo "error: thugir-node/tcsf missing after sparse checkout" >&2
  exit 1
fi

rm -rf "$ENGINE"
mkdir -p "$ENGINE"
# Copy contents so ENGINE_ROOT is the node root (imports: tcsf, nexus, modules).
cp -a "$TMP/repo/thugir-node/." "$ENGINE/"

# Record provenance for operators.
{
  echo "source_repo=$REPO"
  echo "source_ref=$REF"
  echo "synced_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=$(git -C "$TMP/repo" rev-parse HEAD)"
} > "$ENGINE/.thugir-engine-source"

echo "✓ Engine synced → $ENGINE"
echo "  commit $(git -C "$TMP/repo" rev-parse --short HEAD)"
echo "  export THUGIR_ENGINE_ROOT=$ENGINE   # optional; worker auto-detects ./engine"
