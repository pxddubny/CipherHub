package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"

	"github.com/pxddubny/CipherHub/internal/cryptolab/sym"
)

const (
	keySize   = 32
)

func parseHex(value string, size int, name string) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s: неверная hex-строка: %w", name, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%s должен содержать %d байт (%d hex-символов)", name, size, size*2)
	}
	return b, nil
}

func Parse(args []string) (*Config, error) {
	mode := flag.String("mode", "", "encrypt/decrypt")
	blockCipher := flag.String("blockCipher", "", "magma/belt")
	algorithm := flag.String("algorithm", "", "ecb/gamma/cfb")
	input := flag.String("in", "", "input file")
	output := flag.String("out", "", "output file")
	keyHex := flag.String("key", "", "256-bit key in hex")
	ivHex := flag.String("iv", "", "128-bit IV in hex (for cfb)")
	mac := flag.Bool("mac", false, "compute MAC of the plaintext")
	flag.Parse()

	if *mode != "encrypt" && *mode != "decrypt" {
		return nil, errors.New("mode must be encrypt or decrypt")
	}

	if *blockCipher != "magma" && *blockCipher != "belt" {
		return nil, errors.New("blockCipher must be magma or belt")
	}

	if *algorithm != "ecb" && *algorithm != "gamma" && *algorithm != "cfb" {
		return nil, errors.New("algorithm must be ecb, gamma or cfb")
	}

	if *input == "" || *output == "" || *keyHex == "" {
		return nil, errors.New("must specify -in, -out and -key")
	}

	key, err := parseHex(*keyHex, keySize, "key")
	if err != nil {
		return nil, err
	}

	cipher, err := newBlockCipher(*blockCipher, key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if *algorithm == "cfb" || *algorithm == "gamma" {
		if *ivHex == "" {
			return nil, fmt.Errorf("для %s необходимо указать -iv", *algorithm)
		}
		iv, err = parseHex(*ivHex, cipher.BlockSize(), "iv")
		if err != nil {
			return nil, err
		}
	}

	return &Config{
		Mode: *mode,
		BlockCipher: cipher,
		Algorithm: *algorithm,
		Input: *input,
		Output: *output,
		KeyHex: key,
		Iv: iv,
		MAC: *mac,
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