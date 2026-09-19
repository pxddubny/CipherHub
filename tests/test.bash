#!/usr/bin/env bash
set -u

OUT=../txt
mkdir -p "$OUT"

KEY=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

IV_MAGMA=0001020304050607
IV_BELT=000102030405060708090a0b0c0d0e0f

# Извлечь hex-значение имитовставки из вывода CipherHub
extract_mac() {
    grep -oiE 'имитовставка:[[:space:]]*0x[0-9A-Fa-f]+' \
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
run_tests belt "$IV_BELT" ecb cfb