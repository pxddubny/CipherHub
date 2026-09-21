# CipherHub

A command-line tool for symmetric block cipher and asymmetric Rabin encryption, decryption and message authentication.
The symmetric family exposes several block ciphers and modes of operation through a common `BlockCipher` interface;
the asymmetric family implements Rabin public-key encryption.

## Crypto families

Every invocation belongs to one of two families, selected with `-family` (default `sym`):

- **sym** — symmetric block ciphers (Magma, Belt) with the ECB, gamma and CFB modes and MAC.
- **asym** — the Rabin public-key cryptosystem.

The two families are parsed and executed by separate code paths, so flags belonging to the other family are simply
ignored: the `sym` branch only validates cipher/mode/key/IV flags, the `asym` branch only validates Rabin key flags.

## Algorithms

- **Magma** (GOST 28147-89) — 64-bit block, 256-bit key, 32-round Feistel network.
- **Belt** (STB 34.101.31-2011) — 128-bit block, 256-bit key, 8-round SP-network.
- **Rabin** — asymmetric public-key scheme over the modular squaring problem. A 1024-bit private key holds `p`, `q`
  (primes ≡ 3 mod 4), `n = p·q` and the CRT coefficients. Encryption uses only `n`, decryption needs the full
  private key. Each plaintext block is encoded as `0x02 | length | data` and squared modulo `n`; the sender must
  check the congruence condition, receiver picks the correct square root by the `0x02` marker.

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
| `-family`      | `sym` or `asym`                                              | no (default `sym`)                       |
| `-blockCipher` | `magma` or `belt` (sym)                                      | yes (sym)                                |
| `-algorithm`   | `ecb`, `gamma` or `cfb` (sym)                                | yes (sym)                                |
| `-in`          | Path to the input file                                       | yes                                      |
| `-out`         | Path to the output file                                      | yes                                      |
| `-key`         | 256-bit key as a 64-character hex string (sym, INSECURE)     | exactly one of `-key`, `-keyFile`, `-genKey` |
| `-keyFile`     | Path to a file holding the key (hex or raw 32 bytes) (sym)   | exactly one of `-key`, `-keyFile`, `-genKey` |
| `-genKey`      | Generate a fresh key and save it (sym)                       | exactly one of `-key`, `-keyFile`, `-genKey` (encrypt only) |
| `-iv`          | Initialization vector as hex (sym, gamma/cfb)                | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` |
| `-ivFile`      | Path to a file holding the IV (hex or raw bytes) (sym)       | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` |
| `-genIv`       | Generate a random IV and save it raw to the given file (sym) | for gamma/cfb: exactly one of `-iv`, `-ivFile`, `-genIv` (encrypt only) |
| `-mac`         | Compute and verify MAC of the plaintext (magma)              | no                                       |
| `-pubKey`      | Path to the Rabin public key file (asym)                     | asym encrypt: exactly one of `-pubKey`, `-genKey` |
| `-privKey`     | Path to the Rabin private key file (asym)                    | asym decrypt: required (must not be used for encrypting) |
| `-bits`        | Rabin key size in bits, used with `-genKey` (asym)           | no (default 1024, min 16)                |

### Symmetric family rules

The key must be supplied in exactly one way: `-key`, `-keyFile` or `-genKey`. Passing it via `-key`
prints a warning, because command-line arguments are visible in the process list and shell history;
prefer `-keyFile` or `-genKey`. The same applies to the IV for gamma and CFB (`-iv`, `-ivFile` or `-genIv`).
`-genKey` and `-genIv` only make sense when encrypting and are rejected in decrypt mode — for decryption
use the key and IV files they produced.

`-keyFile` and `-ivFile` accept the value either as a hex string or as raw bytes. The file should
contain exactly 64 hex characters / 32 raw bytes for the key, and the block size for the IV.

The IV length must match the block size of the selected cipher: 8 bytes (16 hex characters) for Magma and 16 bytes (32 hex characters) for Belt.

The MAC flag is implemented only by Magma; it is ignored for Belt.

### Asymmetric (Rabin) family rules

Rabin keys are stored as plain text files with one `name=hex` pair per line: the public key holds only `n`,
the private key holds `n`, `p`, `q`, `yp` and `yq` (the file is validated on load, `yp·p + yq·q` must equal 1).

Exactly one of `-pubKey`, `-privKey` and `-genKey` must be given. `-genKey` generates a fresh key pair,
writes the private key to the given path and the public key to `<path>.pub`; it is encrypt-only.
Encryption requires the public side (`-pubKey` or `-genKey`), decryption requires `-privKey` — the public key
cannot decrypt and the private key cannot encrypt (rejected with an error). `-bits` is only consulted when
generating a key.

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

Generate a Rabin key pair (writes `rabin.priv` and `rabin.priv.pub`), encrypt and decrypt:

```
./CipherHub -family asym -mode encrypt -in plaintext.txt -genKey rabin.priv -out ciphertext.bin
./CipherHub -family asym -mode decrypt -in ciphertext.bin -privKey rabin.priv -out decrypted.txt
```

Encrypt with an already generated public key file:

```
./CipherHub -family asym -mode encrypt -in plaintext.txt -pubKey rabin.priv.pub -out ciphertext.bin
```

Generate a smaller key explicitly:

```
./CipherHub -family asym -mode encrypt -in plaintext.txt -genKey lab.priv -bits 512 -out ciphertext.bin
```

## Testing

Shell scripts for end-to-end round-trip tests are available under tests/:

```
cd tests
bash test.bash        # symmetric family
bash test_asym.bash   # asymmetric (Rabin) family
```
`test.bash` encrypts a sample file with each cipher and mode, decrypts the result back and compares it with the
original, prints OK or FAIL for every combination, and additionally covers key/IV delivery via files
(`-keyFile`, `-ivFile`, `-genKey`, `-genIv`) and the error paths of the CLI parser (invalid modes, ciphers,
algorithms, conflicting flags, malformed keys and IVs). `test_asym.bash` covers the Rabin round-trips
(key generation, public/private key files, multi-block messages, custom `-bits`) and the asymmetric validation
errors (family, key-source conflicts, wrong key usage per mode, missing or corrupt key files).