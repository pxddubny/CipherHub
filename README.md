# CipherHub

A command-line tool for symmetric block cipher encryption, decryption and message authentication. 
It implements two algorithms and several modes of operation, exposed through a common `BlockCipher` interface.

## Algorithms

- **Magma** (GOST 28147-89) — 64-bit block, 256-bit key, 32-round Feistel network.
- **Belt** (STB 34.101.31-2011) — 128-bit block, 256-bit key, 8-round SP-network.

## Modes

- **ECB** — electronic codebook (simple substitution). Uses PKCS#7 padding.
- **Gamma** — counter-free gamma feedback mode per GOST 28147-89.
- **CFB** — cipher feedback mode (gamma with ciphertext feedback).
- **MAC** — message authentication code (CBC-MAC per GOST 28147-89).

Not all combinations are meaningful: the original assignment specifies Magma for ECB, gamma, CFB and MAC, and Belt for ECB and CFB only. 
The code itself is mode-agnostic, so any mode can be used with either cipher as long as the IV length matches the block size.

## Build

```sh
git clone https://github.com/pxddubny/CipherHub.git
cd CipherHub
go build
```
The resulting CipherHub binary is self-contained.

## Usage

```
./CipherHub [flags]
```

### Flags

| Flag           | Description                                                  | Required                                 |
|----------------|--------------------------------------------------------------|------------------------------------------|
| `-mode`        | `encrypt` or `decrypt`                                       | yes                                      |
| `-blockCipher` | `magma` or `belt`                                            | yes                                      |
| `-algorithm`   | `ecb`, `gamma` or `cfb`                                      | yes                                      |
| `-in`          | Path to the input file                                       | yes                                      |
| `-out`         | Path to the output file                                      | yes                                      |
| `-key`         | 256-bit key as a 64-character hex string (INSECURE)          | exactly one of `-key`, `-keyFile`, `-genKey` |
| `-keyFile`     | Path to a file holding the key (hex or raw 32 bytes)         | exactly one of `-key`, `-keyFile`, `-genKey` |
| `-genKey`      | Generate a random key and save it raw to the given file      | exactly one of `-key`, `-keyFile`, `-genKey` (encrypt only) |
| `-iv`          | Initialization vector as hex (block size)                    | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` |
| `-ivFile`      | Path to a file holding the IV (hex or raw bytes)             | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` |
| `-genIv`       | Generate a random IV and save it raw to the given file       | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` (encrypt only) |
| `-mac`         | Compute and verify MAC of the plaintext                      | no                                       |

The key must be supplied in exactly one way: `-key`, `-keyFile` or `-genKey`. Passing it via `-key`
prints a warning, because command-line arguments are visible in the process list and shell history;
prefer `-keyFile` or `-genKey`. The same applies to the IV for gamma and CFB (`-iv`, `-ivFile` or `-genIv`).
`-genKey` and `-genIv` only make sense when encrypting and are rejected in decrypt mode — for decryption
use the key and IV files they produced.

`-keyFile` and `-ivFile` accept the value either as a hex string or as raw bytes. The file should
contain exactly 64 hex characters / 32 raw bytes for the key, and the block size for the IV.

The IV length must match the block size of the selected cipher: 8 bytes (16 hex characters) for Magma and 16 bytes (32 hex characters) for Belt.

The MAC flag is implemented only by Magma; it is ignored for Belt.

### Examples

Encrypt a file with Magma in ECB mode:

```sh
./CipherHub -mode encrypt -blockCipher magma -algorithm ecb \
    -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
    -in plaintext.txt -out ciphertext.bin
```

Decrypt the same file:

```
./CipherHub -mode decrypt -blockCipher magma -algorithm ecb \
    -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
    -in ciphertext.bin -out plaintext.txt
```

Encrypt with Belt in CFB mode using a 128-bit IV:

```
./CipherHub -mode encrypt -blockCipher belt -algorithm cfb \
    -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
    -iv 000102030405060708090a0b0c0d0e0f \
    -in plaintext.txt -out ciphertext.bin
```

Load the key from a file (plain hex) with Magma in gamma mode:

```
./CipherHub -mode encrypt -blockCipher magma -algorithm gamma \
    -keyFile key.txt \
    -iv 0001020304050607 \
    -in plaintext.txt -out ciphertext.bin
```

Generate a fresh key and IV, encrypt, then decrypt back from the generated files:

```
./CipherHub -mode encrypt -blockCipher belt -algorithm cfb \
    -genKey mykey.txt -genIv myiv.bin \
    -in plaintext.txt -out ciphertext.bin
./CipherHub -mode decrypt -blockCipher belt -algorithm cfb \
    -keyFile mykey.txt -ivFile myiv.bin \
    -in ciphertext.bin -out decrypted.txt
```

Compute the MAC of a file with Magma:
```
./CipherHub -mode encrypt -blockCipher magma -algorithm ecb \
    -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
    -in plaintext.txt -out ciphertext.bin -mac
```
The MAC is printed to stdout in the form `MAC: 0x%08X`.

## Testing

A shell script for end-to-end round-trip tests of every supported combination is available under tests/:

```
cd tests
bash test.bash
```
It encrypts a sample file with each cipher and mode, decrypts the result back and compares it with the original.
The script prints OK or FAIL for every combination. Besides round-trips it also covers key/IV delivery via files
(`-keyFile`, `-ivFile`, `-genKey`, `-genIv`) and the error paths of the CLI parser (invalid modes, ciphers,
algorithms, conflicting flags, malformed keys and IVs).