# CipherHub

A command-line tool for symmetric block cipher encryption, decryption and message authentication. 
It implements two algorithms and several modes ofoperation, exposed through a common `BlockCipher` interface.

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

./CipherHub [flags]

### Flags

| Flag           | Description                                      | Required |
|----------------|--------------------------------------------------|----------|
| `-mode`        | `encrypt` or `decrypt`                           | yes      |
| `-blockCipher` | `magma` or `belt`                                | yes      |
| `-algorithm`   | `ecb`, `gamma` or `cfb`                          | yes      |
| `-in`          | Path to the input file                           | yes      |
| `-out`         | Path to the output file                          | yes      |
| `-key`         | 256-bit key as a 64-character hex string         | yes      |
| `-iv`          | Initialization vector as hex (block size)        | for gamma and cfb |
| `-mac`         | Compute and verify MAC of the plaintext          | no       |

The IV length must match the block size of the selected cipher: 8 bytes (16 hex characters) for Magma and 16 bytes (32 hex characters) for Belt.

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
Compute the MAC of a file with Magma:
```
./CipherHub -mode encrypt -blockCipher magma -algorithm ecb \
    -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \
    -in plaintext.txt -out ciphertext.bin -mac
```
## Testing

A shell script for end-to-end round-trip tests of every supported combination is available under tests/:

```
cd tests
bash test.sh
```
It encrypts a sample file with each cipher and mode, decrypts the resultback and compares it with the original. 
The script prints OK or FAIL for every combination.

