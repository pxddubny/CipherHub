package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pxddubny/CipherHub/internal/cryptolab/sym"
)

const keySize = 32

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
	blockCipher := flag.String("blockCipher", "", "block cipher: magma or belt")
	algorithm := flag.String("algorithm", "", "algorithm: ecb, gamma or cfb")
	input := flag.String("in", "", "input file path")
	output := flag.String("out", "", "output file path")
	keyHex := flag.String("key", "", "256-bit key in hex (INSECURE, use -keyFile or -genKey instead)")
	keyFile := flag.String("keyFile", "", "path to file containing the key (hex or raw 32 bytes)")
	genKey := flag.String("genKey", "", "generate a random 256-bit key and save to the specified file")
	ivHex := flag.String("iv", "", "IV in hex (required for gamma/cfb)")
	ivFile := flag.String("ivFile", "", "path to file containing the IV (hex or raw)")
	genIv := flag.String("genIv", "", "generate a random IV and save to the specified file")
	mac := flag.Bool("mac", false, "compute MAC (имитовставка) of the plaintext")
	flag.Parse()

	if *mode != "encrypt" && *mode != "decrypt" {
		return nil, errors.New("mode must be 'encrypt' or 'decrypt'")
	}

	if *mode == "decrypt" {
		if *genKey != "" {
			return nil, errors.New("genKey cannot be used in decrypt mode: keys are only generated for encryption, use -key or -keyFile to decrypt")
		}
		if *genIv != "" {
			return nil, errors.New("genIv cannot be used in decrypt mode: IVs are only generated for encryption, use -iv or -ivFile to decrypt")
		}
	}

	if *blockCipher != "magma" && *blockCipher != "belt" {
		return nil, errors.New("blockCipher must be 'magma' or 'belt'")
	}

	if *algorithm != "ecb" && *algorithm != "gamma" && *algorithm != "cfb" {
		return nil, errors.New("algorithm must be 'ecb', 'gamma' or 'cfb'")
	}

	if *input == "" || *output == "" {
		return nil, errors.New("-in and -out are required")
	}

	key, err := resolveKey(*keyHex, *keyFile, *genKey)
	if err != nil {
		return nil, err
	}

	cipher, err := newBlockCipher(*blockCipher, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if *algorithm == "cfb" || *algorithm == "gamma" {
		iv, err = resolveIV(*ivHex, *ivFile, *genIv, cipher.BlockSize())
		if err != nil {
			return nil, err
		}
	}

	return &Config{
		Mode:        *mode,
		BlockCipher: cipher,
		Algorithm:   *algorithm,
		Input:       *input,
		Output:      *output,
		KeyHex:      key,
		Iv:          iv,
		MAC:         *mac,
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
