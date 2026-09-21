#!/usr/bin/env bash
set -eu

OUT=../txt
BIN=../CipherHub
mkdir -p "$OUT"

if [ ! -f "$OUT/input.txt" ]; then
    echo "Hello, World! This is a test for CipherHub." > "$OUT/input.txt"
fi

if [ ! -x "$BIN" ]; then
    go build -o "$BIN" ..
fi

MODES="encrypt decrypt"

echo "=== RABIN (asym) ==="

# ---- Round-trip: generate keypair, encrypt with -genKey, decrypt with -privKey ----
PRIV="$OUT/rabin_priv.txt"
ENC="$OUT/rabin_gen.bin"
DEC="$OUT/rabin_gen.txt"
rm -f "$PRIV" "$PRIV.pub" "$ENC" "$DEC"

"$BIN" -family asym -mode encrypt -in "$OUT/input.txt" -genKey "$PRIV" -out "$ENC" >/dev/null
[ -f "$PRIV" ] && [ -f "$PRIV.pub" ] && echo "OK:   genKey writes private+public key files"
"$BIN" -family asym -mode decrypt -in "$ENC" -privKey "$PRIV" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" >/dev/null; then
    echo "OK:   rabin genKey/privKey round-trip"
else
    echo "FAIL: rabin genKey/privKey round-trip"
fi

# ---- Round-trip: encrypt with -pubKey, decrypt with -privKey ----
ENC="$OUT/rabin_pub.bin"
DEC="$OUT/rabin_pub.txt"
rm -f "$ENC" "$DEC"
"$BIN" -family asym -mode encrypt -in "$OUT/input.txt" -pubKey "$PRIV.pub" -out "$ENC"
"$BIN" -family asym -mode decrypt -in "$ENC" -privKey "$PRIV" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" >/dev/null; then
    echo "OK:   rabin pubKey/privKey round-trip"
else
    echo "FAIL: rabin pubKey/privKey round-trip"
fi

# ---- Round-trip: multi-block input (> one Rabin block) ----
BIG="$OUT/rabin_big_input.txt"
ENC="$OUT/rabin_big.bin"
DEC="$OUT/rabin_big.txt"
printf 'x%.0s' {1..2000} > "$BIG"
rm -f "$ENC" "$DEC"
"$BIN" -family asym -mode encrypt -in "$BIG" -pubKey "$PRIV.pub" -out "$ENC"
"$BIN" -family asym -mode decrypt -in "$ENC" -privKey "$PRIV" -out "$DEC"
if cmp -s "$BIG" "$DEC"; then
    echo "OK:   rabin multi-block (2000 bytes) round-trip"
else
    echo "FAIL: rabin multi-block round-trip"
fi

# ---- Round-trip: small key via -bits ----
PRIV256="$OUT/rabin_priv256.txt"
ENC="$OUT/rabin_256.bin"
DEC="$OUT/rabin_256.txt"
rm -f "$PRIV256" "$PRIV256.pub" "$ENC" "$DEC"
"$BIN" -family asym -mode encrypt -in "$OUT/input.txt" -genKey "$PRIV256" -bits 256 -out "$ENC" >/dev/null
"$BIN" -family asym -mode decrypt -in "$ENC" -privKey "$PRIV256" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" >/dev/null; then
    echo "OK:   rabin round-trip with -bits 256"
else
    echo "FAIL: rabin round-trip with -bits 256"
fi

# ---- Wrong key decryption must fail (corrupt the file) ----
CORR="$OUT/rabin_corrupt.txt"
cp "$PRIV" "$CORR"
tr '0123456789abcdef' 'abcdef0123456789' < "$CORR" > "$CORR.rot" && mv "$CORR.rot" "$CORR"
out=$("$BIN" -family asym -mode decrypt -in "$ENC" -privKey "$CORR" -out "$DEC" 2>&1) && {
    echo "FAIL: corrupt key file was accepted"
} || {
    echo "OK:   corrupt private key rejected"
}

echo
echo "=== VALIDATION ERRORS (parseAsym) ==="

expect_fail() {
    local desc=$1 expected=$2
    shift 2
    local out
    out=$("$@" 2>&1) && {
        echo "FAIL(should have errored): $desc"
        return
    }
    if ! printf '%s\n' "$out" | grep -qiFe "$expected"; then
        echo "FAIL(expected msg '$expected'): $desc"
        return
    fi
    echo "OK:   $desc (rejected)"
}

expect_fail "invalid family"          "family must be" \
    "$BIN" -family rsa -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key 0000000000000000000000000000000000000000000000000000000000000000
expect_fail "no key for rabin"        "key is required for Rabin" \
    "$BIN" -family asym -mode encrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin"
expect_fail "pubKey + privKey conflict" "mutually exclusive" \
    "$BIN" -family asym -mode encrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -pubKey "$PRIV.pub" -privKey "$PRIV"
expect_fail "pubKey + genKey conflict"  "mutually exclusive" \
    "$BIN" -family asym -mode encrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -pubKey "$PRIV.pub" -genKey "$PRIV"
expect_fail "genKey in decrypt"       "cannot be used in decrypt" \
    "$BIN" -family asym -mode decrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -genKey "$PRIV"
expect_fail "pubKey in decrypt"       "cannot be used for decrypting" \
    "$BIN" -family asym -mode decrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -pubKey "$PRIV.pub"
expect_fail "privKey in encrypt"      "cannot be used for encrypting" \
    "$BIN" -family asym -mode encrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -privKey "$PRIV"
expect_fail "missing pubKey file"     "pubKey:" \
    "$BIN" -family asym -mode encrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -pubKey "$OUT/nonexistent.pub"
expect_fail "missing privKey file"    "privKey:" \
    "$BIN" -family asym -mode decrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -privKey "$OUT/nonexistent.txt"

printf 'n=5\nq=3\n' > "$OUT/rabin_trunc.txt"
expect_fail "privKey file missing fields" "missing field" \
    "$BIN" -family asym -mode decrypt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -privKey "$OUT/rabin_trunc.txt"