#!/bin/sh
# Builds a signed test bundle from rules/ with throwaway keys (1-of-1 root) for
# PokeyRulesTests: <out>/rules.bundle and <out>/roots.txt.
set -eu
CORE=$(cd "$(dirname "$0")/../../core" && pwd)
OUT=${1:?usage: make-test-bundle.sh OUTDIR}
mkdir -p "$OUT"
cargo build --quiet --release -p pokey-rulec --manifest-path "$CORE/Cargo.toml"
RULEC="$CORE/target/release/pokey-rulec"
K=$(mktemp -d)
trap 'rm -rf "$K"' EXIT
"$RULEC" keygen --out "$K/root" >/dev/null
"$RULEC" keygen --out "$K/release" >/dev/null
NOW=$(date +%s)
"$RULEC" cert-new --release-pub "$K/release.pub" --not-before $((NOW - 60)) --not-after $((NOW + 86400 * 30)) \
    --channels stable,canary --out "$K/release.cert" >/dev/null
"$RULEC" cert-sign --cert "$K/release.cert" --root-key "$K/root.key" >/dev/null
"$RULEC" compile --rules "$CORE/../rules" --version 7 --channel stable --expires-days 30 --out "$K/unsigned" >/dev/null
"$RULEC" sign --in "$K/unsigned" --cert "$K/release.cert" --key-file "$K/release.key" --out "$OUT/rules.bundle" >/dev/null
cp "$K/root.pub" "$OUT/roots.txt"
