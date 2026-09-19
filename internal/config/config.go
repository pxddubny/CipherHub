package config

import "github.com/pxddubny/CipherHub/internal/cryptolab/sym"

type Config struct {
	Mode string
	BlockCipher sym.BlockCipher
	Algorithm string
	Input string
	Output string
	KeyHex []byte
	Iv []byte
	MAC bool
}