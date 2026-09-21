package config

import (
	"github.com/pxddubny/CipherHub/internal/cryptolab/asym/rabin"
	"github.com/pxddubny/CipherHub/internal/cryptolab/sym"
)

type Family string

const (
	FamilySym  Family = "sym"
	FamilyAsym Family = "asym"
)

type Config struct {
	Family    Family
	Mode      string
	Algorithm string
	Input     string
	Output    string
	MAC       bool

	BlockCipher sym.BlockCipher
	Key         []byte
	Iv          []byte

	PublicKey  *rabin.PublicKey
	PrivateKey *rabin.PrivateKey
}
