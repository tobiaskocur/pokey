#!/usr/bin/env bash
# Terminal demo for the README (recorded into docs/assets/rule-pipeline.gif).
# Throwaway keys in a temp dir; nothing here is a real identity.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
export PATH="$ROOT/core/target/release:$PATH"
W=$(mktemp -d); cd "$W"; ln -s "$ROOT/rules" rules
run() { printf '\n\033[1;32m$\033[0m %s\n' "$*"; sleep 0.6; "$@"; }
say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep 0.8; }

say "two offline roots and one release key"
run edr-rulec keygen --out root1 >/dev/null
run edr-rulec keygen --out root2 >/dev/null
run edr-rulec keygen --out release >/dev/null
cat root1.pub root2.pub > roots.txt
now=$(date +%s)
say "both roots certify the release key (2-of-2)"
run edr-rulec cert-new --release-pub release.pub --not-before $now --not-after $((now + 86400 * 90)) --channels stable --out release.cert
run edr-rulec cert-sign --cert release.cert --root-key root1.key
run edr-rulec cert-sign --cert release.cert --root-key root2.key

say "lint, fixtures and benign corpus, then compile and sign"
run edr-rulec test --rules rules --benign rules/benign --max-ms 50 --max-fuel-pct 50
run edr-rulec compile --rules rules --version 7 --channel stable --expires-days 30 --out unsigned.bundle
run edr-rulec sign --in unsigned.bundle --cert release.cert --key-file release.key --out rules-7.bundle
run edr-rulec verify --bundle rules-7.bundle --roots roots.txt --threshold 2 --self-test

say "flip one byte in the signed bundle: verification fails"
size=$(wc -c < rules-7.bundle)
cp rules-7.bundle tampered.bundle
printf '\001' | dd of=tampered.bundle bs=1 seek=$((size - 100)) conv=notrunc 2>/dev/null
run edr-rulec verify --bundle tampered.bundle --roots roots.txt --threshold 2 || true

say "scan: a PNG with a Mach-O appended and a valid PNG"
cp rules/fixtures/png_trailing_macho.png macho.png; cp rules/fixtures/png_valid.png valid.png
run edr-rulec scan --bundle rules-7.bundle --roots roots.txt --threshold 2 macho.png valid.png
sleep 2
