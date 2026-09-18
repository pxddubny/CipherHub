package config

import "github.com/pxddubny/CipherHub/internal/cryptolab"

type Config struct {
	Mode string
	BlockCipher cryptolab.BlockCipher
	Algorithm string
	Input string
	Output string
	KeyHex []byte
	Iv []byte
	MAC bool
}