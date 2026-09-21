package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pxddubny/CipherHub/internal/cryptolab/asym/rabin"
	"github.com/pxddubny/CipherHub/internal/cryptolab/sym"
)

const (
	keySize          = 32
	defaultRabinBits = 1024
)

func parseHex(value string, size int, name string) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex string: %w", name, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%s must contain %d bytes (%d hex characters)", name, size, size*2)
	}
	return b, nil
}

func Parse(args []string) (*Config, error) {
	mode := flag.String("mode", "", "encrypt or decrypt")
	family := flag.String("family", "sym", "crypto family: sym or asym")
	input := flag.String("in", "", "input file path")
	output := flag.String("out", "", "output file path")

	blockCipher := flag.String("blockCipher", "", "block cipher: magma or belt")
	algorithm := flag.String("algorithm", "", "algorithm: ecb, gamma or cfb")
	keyHex := flag.String("key", "", "256-bit key in hex (INSECURE, use -keyFile or -genKey instead)")
	keyFile := flag.String("keyFile", "", "path to file containing the key (hex or raw 32 bytes)")
	genKey := flag.String("genKey", "", "generate a random key and save it to the specified file")
	ivHex := flag.String("iv", "", "IV in hex (required for gamma/cfb)")
	ivFile := flag.String("ivFile", "", "path to file containing the IV (hex or raw)")
	genIv := flag.String("genIv", "", "generate a random IV and save to the specified file")
	mac := flag.Bool("mac", false, "compute MAC (имитовставка) of the plaintext (magma only)")

	pubKey := flag.String("pubKey", "", "path to the Rabin public key file (for encryption)")
	privKey := flag.String("privKey", "", "path to the Rabin private key file (for decryption)")
	bits := flag.Int("bits", defaultRabinBits, "Rabin key size in bits (used with -genKey)")

	flag.Parse()

	if *mode != "encrypt" && *mode != "decrypt" {
		return nil, errors.New("mode must be 'encrypt' or 'decrypt'")
	}

	if *input == "" || *output == "" {
		return nil, errors.New("-in and -out are required")
	}

	if *mode == "decrypt" && *genKey != "" {
		return nil, errors.New("genKey cannot be used in decrypt mode: keys are only generated for encryption, use -key/-keyFile (sym) or -privKey (asym) to decrypt")
	}

	if *mode == "decrypt" && *genIv != "" {
		return nil, errors.New("genIv cannot be used in decrypt mode: IVs are only generated for encryption, use -iv or -ivFile to decrypt")
	}

	switch Family(*family) {
	case FamilySym:
		return parseSym(*mode, *blockCipher, *algorithm, *keyHex, *keyFile, *genKey, *ivHex, *ivFile, *genIv, *mac, *input, *output)
	case FamilyAsym:
		return parseAsym(*mode, *pubKey, *privKey, *genKey, *bits, *input, *output)
	default:
		return nil, fmt.Errorf("family must be 'sym' or 'asym', got %q", *family)
	}
}

func parseSym(mode, blockCipher, algorithm, keyHex, keyFile, genKey, ivHex, ivFile, genIv string, mac bool, input, output string) (*Config, error) {
	if blockCipher != "magma" && blockCipher != "belt" {
		return nil, errors.New("blockCipher must be 'magma' or 'belt'")
	}

	if algorithm != "ecb" && algorithm != "gamma" && algorithm != "cfb" {
		return nil, errors.New("algorithm must be 'ecb', 'gamma' or 'cfb'")
	}

	key, err := resolveKey(keyHex, keyFile, genKey)
	if err != nil {
		return nil, err
	}

	cipher, err := newBlockCipher(blockCipher, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if algorithm == "cfb" || algorithm == "gamma" {
		iv, err = resolveIV(ivHex, ivFile, genIv, cipher.BlockSize())
		if err != nil {
			return nil, err
		}
	}

	return &Config{
		Family:      FamilySym,
		Mode:        mode,
		Algorithm:   algorithm,
		Input:       input,
		Output:      output,
		BlockCipher: cipher,
		Key:         key,
		Iv:          iv,
		MAC:         mac,
	}, nil
}

func parseAsym(mode, pubKey, privKey, genKey string, bits int, input, output string) (*Config, error) {
	var sources []string
	if pubKey != "" {
		sources = append(sources, "pubKey")
	}
	if privKey != "" {
		sources = append(sources, "privKey")
	}
	if genKey != "" {
		sources = append(sources, "genKey")
	}

	if len(sources) == 0 {
		return nil, errors.New("key is required for Rabin: use -pubKey, -privKey or -genKey")
	}
	if len(sources) > 1 {
		return nil, fmt.Errorf("flags %s are mutually exclusive, specify only one", strings.Join(sources, ", "))
	}

	var public *rabin.PublicKey
	var private *rabin.PrivateKey

	switch {
	case genKey != "":
		gen, err := rabin.GenerateKey(bits)
		if err != nil {
			return nil, fmt.Errorf("genKey: %w", err)
		}
		pubPath := genKey + ".pub"
		if err := gen.Save(genKey); err != nil {
			return nil, fmt.Errorf("genKey: cannot save private key to %s: %w", genKey, err)
		}
		if err := gen.Public.Save(pubPath); err != nil {
			return nil, fmt.Errorf("genKey: cannot save public key to %s: %w", pubPath, err)
		}
		fmt.Fprintf(os.Stdout, "generated Rabin keypair: private key -> %s, public key -> %s (n: %d bits)\n",
			genKey, pubPath, gen.Public.N.BitLen())
		public = &gen.Public

	case pubKey != "":
		if mode == "decrypt" {
			return nil, errors.New("public key cannot be used for decrypting, use -privKey instead")
		}
		loaded, err := rabin.LoadPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("pubKey: %w", err)
		}
		public = loaded

	case privKey != "":
		if mode == "encrypt" {
			return nil, errors.New("private key cannot be used for encrypting, use -pubKey or -genKey instead")
		}
		loaded, err := rabin.LoadPrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("privKey: %w", err)
		}
		private = loaded
	}

	return &Config{
		Family:     FamilyAsym,
		Mode:       mode,
		Input:      input,
		Output:     output,
		PublicKey:  public,
		PrivateKey: private,
	}, nil
}

func newBlockCipher(name string, key []byte) (sym.BlockCipher, error) {
	switch name {
	case "magma":
		return sym.NewMagma(key)
	case "belt":
		return sym.NewBelt(key)
	default:
		return nil, fmt.Errorf("unknown block cipher: %s", name)
	}
}

func resolveKey(keyArg, keyFileArg, genKeyArg string) ([]byte, error) {
	var sources []string
	if keyArg != "" {
		sources = append(sources, "key")
	}
	if keyFileArg != "" {
		sources = append(sources, "keyFile")
	}
	if genKeyArg != "" {
		sources = append(sources, "genKey")
	}

	if len(sources) == 0 {
		return nil, errors.New("key is required: use -key, -keyFile or -genKey")
	}
	if len(sources) > 1 {
		return nil, fmt.Errorf("flags %s are mutually exclusive, specify only one", strings.Join(sources, ", "))
	}

	switch {
	case keyArg != "":
		fmt.Fprintf(os.Stderr, "WARNING: passing the encryption key via -key is insecure.\n"+
			"Arguments are visible in the process list (ps) and saved in shell history.\n"+
			"Use -keyFile or -genKey instead.\n")
		reader := &argReader{value: keyArg}
		return reader.Read(keySize, "key")
	case keyFileArg != "":
		reader := &fileReader{path: keyFileArg}
		return reader.Read(keySize, "key")
	default:
		reader := &randReader{savePath: genKeyArg}
		return reader.Read(keySize, "key")
	}
}

func resolveIV(ivArg, ivFileArg, genIvArg string, blockSize int) ([]byte, error) {
	var sources []string
	if ivArg != "" {
		sources = append(sources, "iv")
	}
	if ivFileArg != "" {
		sources = append(sources, "ivFile")
	}
	if genIvArg != "" {
		sources = append(sources, "genIv")
	}

	if len(sources) == 0 {
		return nil, errors.New("IV is required for this algorithm: use -iv, -ivFile or -genIv")
	}
	if len(sources) > 1 {
		return nil, fmt.Errorf("flags %s are mutually exclusive, specify only one", strings.Join(sources, ", "))
	}

	switch {
	case ivArg != "":
		reader := &argReader{value: ivArg}
		return reader.Read(blockSize, "iv")
	case ivFileArg != "":
		reader := &fileReader{path: ivFileArg}
		return reader.Read(blockSize, "iv")
	default:
		reader := &randReader{savePath: genIvArg}
		return reader.Read(blockSize, "iv")
	}
}
