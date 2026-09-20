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

KEY=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

IV_MAGMA=0001020304050607
IV_BELT=000102030405060708090a0b0c0d0e0f

# Извлечь hex-значение имитовставки из вывода CipherHub
extract_mac() {
    grep -oiE 'MAC:[[:space:]]*0x[0-9A-Fa-f]+' \
        | grep -oiE '0x[0-9A-Fa-f]+' \
        | head -n1
}

run_tests() {
    local cipher=$1
    local iv=$2
    shift 2
    local algos=("$@")

    for algo in "${algos[@]}"; do
        # MAC поддерживается только у magma
        local macflags=("")
        [ "$cipher" = "magma" ] && macflags=("" "-mac")

        for macflag in "${macflags[@]}"; do
            local suffix
            suffix=$(echo "$macflag" | tr -d '-')
            [ -z "$suffix" ] && suffix=plain

            local ivflag=""
            [ "$algo" != "ecb" ] && ivflag="-iv $iv"

            local ENC="$OUT/enc_${cipher}_${algo}_${suffix}.bin"
            local DEC="$OUT/dec_${cipher}_${algo}_${suffix}.txt"

            local enc_out dec_out
            enc_out=$(../CipherHub -mode encrypt -algorithm "$algo" -blockCipher "$cipher" \
                        -in "$OUT/input.txt" -key "$KEY" $ivflag $macflag -out "$ENC" 2>&1) || {
                echo "FAIL(enc): $cipher $algo $suffix"
                continue
            }

            dec_out=$(../CipherHub -mode decrypt -algorithm "$algo" -blockCipher "$cipher" \
                        -in "$ENC" -key "$KEY" $ivflag $macflag -out "$DEC" 2>&1) || {
                echo "FAIL(dec): $cipher $algo $suffix"
                continue
            }

            # --- Проверка имитовставки ---
            local mac_before="" mac_after="" mac_note=""
            if [ -n "$macflag" ]; then
                mac_before=$(printf '%s\n' "$enc_out" | extract_mac)
                mac_after=$(printf '%s\n'  "$dec_out" | extract_mac)
                if [ -n "$mac_before" ] && [ "$mac_before" = "$mac_after" ]; then
                    mac_note=" | MAC до=$mac_before после=$mac_after [MATCH]"
                else
                    mac_note=" | MAC до=${mac_before:-?} после=${mac_after:-?} [MISMATCH]"
                fi
            fi

            # --- Проверка содержимого ---
            if diff -q "$OUT/input.txt" "$DEC" > /dev/null; then
                echo "OK:   $cipher $algo $suffix${mac_note}"
            else
                echo "FAIL: $cipher $algo $suffix${mac_note}"
            fi
        done
    done
}

echo "=== MAGMA ==="
run_tests magma "$IV_MAGMA" ecb gamma cfb

echo
echo "=== BELT ==="
run_tests belt "$IV_BELT" ecb gamma cfb

echo
echo "=== KEY/IV FROM FILES (round-trips) ==="

KEY_HEX="$OUT/key_hex.txt"
KEY_RAW="$OUT/key_raw.bin"
IV_HEX="$OUT/iv_hex.txt"
KEY_GEN="$OUT/key_gen.bin"
IV_GEN="$OUT/iv_gen.bin"
KEY_BAD="$OUT/key_bad.txt"

printf '%s\n' "$KEY" > "$KEY_HEX"
printf 'A%.0s' {1..32} > "$KEY_RAW"
printf '%s\n' "$IV_MAGMA" > "$IV_HEX"
printf 'short' > "$KEY_BAD"

# keyFile (hex) + ivFile (hex): magma gamma
ENC="$OUT/enc_keyfile.bin"; DEC="$OUT/dec_keyfile.txt"
"$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -keyFile "$KEY_HEX" -ivFile "$IV_HEX" -out "$ENC"
"$BIN" -mode decrypt -algorithm gamma -blockCipher magma \
    -in "$ENC" -keyFile "$KEY_HEX" -ivFile "$IV_HEX" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" > /dev/null; then
    echo "OK:   keyFile/ivFile magma gamma"
else
    echo "FAIL: keyFile/ivFile magma gamma"
fi

# keyFile (raw 32 bytes): belt ecb
ENC="$OUT/enc_keyraw.bin"; DEC="$OUT/dec_keyraw.txt"
"$BIN" -mode encrypt -algorithm ecb -blockCipher belt \
    -in "$OUT/input.txt" -keyFile "$KEY_RAW" -out "$ENC"
"$BIN" -mode decrypt -algorithm ecb -blockCipher belt \
    -in "$ENC" -keyFile "$KEY_RAW" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" > /dev/null; then
    echo "OK:   keyFile(raw) belt ecb"
else
    echo "FAIL: keyFile(raw) belt ecb"
fi

# genKey + genIv: generate on encrypt, decrypt back from files
ENC="$OUT/enc_gen.bin"; DEC="$OUT/dec_gen.txt"
"$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -genKey "$KEY_GEN" -genIv "$IV_GEN" -out "$ENC" >/dev/null
"$BIN" -mode decrypt -algorithm gamma -blockCipher magma \
    -in "$ENC" -keyFile "$KEY_GEN" -ivFile "$IV_GEN" -out "$DEC"
if diff -q "$OUT/input.txt" "$DEC" > /dev/null; then
    echo "OK:   genKey/genIv magma gamma"
else
    echo "FAIL: genKey/genIv magma gamma"
fi

echo
echo "=== VALIDATION ERRORS (parse.go) ==="

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

expect_fail "invalid mode"        "mode must be" \
    "$BIN" -mode derypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY"
expect_fail "invalid blockCipher" "blockCipher must be" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher aes \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY"
expect_fail "invalid algorithm"   "algorithm must be" \
    "$BIN" -mode encrypt -algorithm cbc -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY"
expect_fail "missing -in"         "-in and -out are required" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -out "$OUT/x.bin" -key "$KEY"
expect_fail "missing -out"        "-in and -out are required" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -key "$KEY"
expect_fail "no key"              "key is required" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin"
expect_fail "genKey in decrypt"   "cannot be used in decrypt" \
    "$BIN" -mode decrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -genKey "$OUT/x_key.bin"
expect_fail "genIv in decrypt"    "cannot be used in decrypt" \
    "$BIN" -mode decrypt -algorithm cfb -blockCipher belt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY" -genIv "$OUT/x_iv.bin"
expect_fail "key + keyFile conflict" "mutually exclusive" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY" -keyFile "$KEY_HEX"
expect_fail "invalid key hex"     "invalid hex" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "ZZZZ"
expect_fail "short key"           "must contain 32 bytes" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$(printf 'AB%.0s' {1..31})"
expect_fail "missing IV (gamma)"  "IV is required" \
    "$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY"
expect_fail "iv + ivFile conflict" "mutually exclusive" \
    "$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY" -iv "$IV_MAGMA" -ivFile "$IV_HEX"
expect_fail "invalid iv hex"      "invalid hex" \
    "$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY" -iv "GGGG"
expect_fail "short iv (magma)"    "must contain 8 bytes" \
    "$BIN" -mode encrypt -algorithm gamma -blockCipher magma \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -key "$KEY" -iv "00010203040506"
expect_fail "missing keyFile"     "cannot read file" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher belt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -keyFile "$OUT/nonexistent.bin"
expect_fail "keyFile wrong size"  "unexpected size" \
    "$BIN" -mode encrypt -algorithm ecb -blockCipher belt \
    -in "$OUT/input.txt" -out "$OUT/x.bin" -keyFile "$KEY_BAD"