#!/usr/bin/env bash
set -u

OUT=../txt
mkdir -p "$OUT"

KEY=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

IV_MAGMA=0001020304050607
IV_BELT=000102030405060708090a0b0c0d0e0f

run_tests() {
    local cipher=$1
    local iv=$2
    shift 2
    local algos=("$@")

    for algo in "${algos[@]}"; do
        # MAC только для magma
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

            ../CipherHub -mode encrypt -algorithm "$algo" -blockCipher "$cipher" \
                -in "$OUT/input.txt" -key "$KEY" $ivflag $macflag -out "$ENC" || {
                echo "FAIL(enc): $cipher $algo $suffix"
                continue
            }

            ../CipherHub -mode decrypt -algorithm "$algo" -blockCipher "$cipher" \
                -in "$ENC" -key "$KEY" $ivflag $macflag -out "$DEC" || {
                echo "FAIL(dec): $cipher $algo $suffix"
                continue
            }

            if diff -q "$OUT/input.txt" "$DEC" > /dev/null; then
                echo "OK:   $cipher $algo $suffix"
            else
                echo "FAIL: $cipher $algo $suffix"
            fi
        done
    done
}

echo "=== MAGMA ==="
run_tests magma "$IV_MAGMA" ecb gamma cfb

echo
echo "=== BELT ==="
run_tests belt "$IV_BELT" ecb cfb