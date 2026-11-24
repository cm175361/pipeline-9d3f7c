#!/bin/sh
# source-vault.sh — encrypt/decrypt the whole source tree into a
# single authenticated archive (public-build pipeline, pre-staged
# in package 10; first used for real in package 11).
#
# Why: from package 11 the build runs in a PUBLIC GitHub repo
# (free unlimited Actions minutes). The user's hard rule: the
# source must be encrypted for the ENTIRE exposure window — a
# clone of the public repo yields ciphertext only. The key lives
# in the repo's Actions secrets (SOURCE_VAULT_KEY_HEX), never in
# the repo, never in logs.
#
# Format:  IV(16) || AES-256-CBC ciphertext || HMAC-SHA256(32)
#          encrypt-then-MAC over IV||ciphertext, both keys derived
#          from the one master key by domain-separated SHA-256.
# openssl `enc` has no AEAD mode on either platform, hence the
# explicit HMAC; decrypt verifies it BEFORE decrypting and fails
# closed on any mismatch.
#
# Usage:
#   SOURCE_VAULT_KEY_HEX=<64 hex> tools/source-vault.sh encrypt <srcdir> <vaultfile>
#   SOURCE_VAULT_KEY_HEX=<64 hex> tools/source-vault.sh decrypt <vaultfile> <outdir>
#
# The plaintext archive inside is a gzipped tar of <srcdir>
# (excluding .git). Nothing here ever prints key material.
set -eu

MODE="${1:-}"
KEY_HEX="${SOURCE_VAULT_KEY_HEX:-}"

die() { echo "source-vault: $*" >&2; exit 1; }

[ -n "$KEY_HEX" ] || die "SOURCE_VAULT_KEY_HEX is not set"
[ "${#KEY_HEX}" -eq 64 ] || die "key must be 64 hex chars (32 bytes)"
case "$KEY_HEX" in *[!0-9a-fA-F]*) die "key must be hex" ;; esac

hex2bin() { perl -e 'print pack("H*", $ARGV[0])' "$1"; }

# Hex string ($1) written as raw bytes to file ($2).
write_key_bytes() { hex2bin "$1" > "$2"; }

derive() {
    # $1 = domain label; prints derived key hex (SHA-256 of
    # master-key-bytes || label).
    _tmp=$(mktemp)
    write_key_bytes "$KEY_HEX" "$_tmp"
    printf '%s' "$1" >> "$_tmp"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_tmp" | cut -d' ' -f1
    else
        shasum -a 256 "$_tmp" | cut -d' ' -f1
    fi
    rm -f "$_tmp"
}

hmac_file() {
    # $1 = mac key hex, $2 = file; prints HMAC-SHA256 hex.
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" "$2" 2>/dev/null | sed 's/.*= //'
}

case "$MODE" in
encrypt)
    SRC="${2:-}"; OUT="${3:-}"
    [ -n "$SRC" ] && [ -n "$OUT" ] || die "usage: encrypt <srcdir> <vaultfile>"
    [ -d "$SRC" ] || die "srcdir not found: $SRC"
    ENC_KEY=$(derive "xudong-vault-enc-v1")
    MAC_KEY=$(derive "xudong-vault-mac-v1")
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    tar --exclude='.git' --exclude='build' -czf "$WORK/plain.tar.gz" -C "$SRC" .
    IV_HEX=$(openssl rand -hex 16)
    write_key_bytes "$IV_HEX" "$WORK/iv.bin"
    openssl enc -aes-256-cbc -K "$ENC_KEY" -iv "$IV_HEX" \
        -in "$WORK/plain.tar.gz" -out "$WORK/cipher.bin"
    cat "$WORK/iv.bin" "$WORK/cipher.bin" > "$WORK/body.bin"
    HMAC_HEX=$(hmac_file "$MAC_KEY" "$WORK/body.bin")
    write_key_bytes "$HMAC_HEX" "$WORK/mac.bin"
    cat "$WORK/body.bin" "$WORK/mac.bin" > "$OUT"
    echo "source-vault: encrypted $SRC -> $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
    ;;
decrypt)
    VAULT="${2:-}"; OUTDIR="${3:-}"
    [ -n "$VAULT" ] && [ -n "$OUTDIR" ] || die "usage: decrypt <vaultfile> <outdir>"
    [ -f "$VAULT" ] || die "vault file not found: $VAULT"
    ENC_KEY=$(derive "xudong-vault-enc-v1")
    MAC_KEY=$(derive "xudong-vault-mac-v1")
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    SIZE=$(wc -c < "$VAULT" | tr -d ' ')
    [ "$SIZE" -gt 48 ] || die "vault file too small"
    head -c $((SIZE - 32)) "$VAULT" > "$WORK/body.bin"
    tail -c 32 "$VAULT" > "$WORK/mac.bin"
    EXPECT_HEX=$(hmac_file "$MAC_KEY" "$WORK/body.bin")
    ACTUAL_HEX=$(od -An -tx1 "$WORK/mac.bin" | tr -d ' \n')
    [ "$EXPECT_HEX" = "$ACTUAL_HEX" ] || die "HMAC verification failed — refusing to decrypt"
    head -c 16 "$WORK/body.bin" > "$WORK/iv.bin"
    IV_HEX=$(od -An -tx1 "$WORK/iv.bin" | tr -d ' \n')
    tail -c $((SIZE - 32 - 16)) "$WORK/body.bin" > "$WORK/cipher.bin"
    openssl enc -d -aes-256-cbc -K "$ENC_KEY" -iv "$IV_HEX" \
        -in "$WORK/cipher.bin" -out "$WORK/plain.tar.gz"
    mkdir -p "$OUTDIR"
    tar -xzf "$WORK/plain.tar.gz" -C "$OUTDIR"
    echo "source-vault: decrypted $VAULT -> $OUTDIR (HMAC verified)"
    ;;
*)
    die "usage: source-vault.sh encrypt|decrypt ..."
    ;;
esac
