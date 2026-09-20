package sym

import (
	"fmt"

	"github.com/pxddubny/CipherHub/internal/padding"
)

type ecb struct {
	bc BlockCipher
}

func NewECB(bc BlockCipher) Mode {
	return &ecb{bc: bc}
}

func (e *ecb) Encrypt(src []byte) []byte {
	bs := e.bc.BlockSize()
	padded := padding.Pad(src, bs)
	out := make([]byte, len(padded))

	for i := 0; i < len(padded); i += bs {
		e.bc.EncryptBlock(out[i:i+bs], padded[i:i+bs])
	}
	return out
}

func (e *ecb) Decrypt(src []byte) []byte {
	bs := e.bc.BlockSize()
	if len(src)%bs != 0 {
		panic(fmt.Sprintf("ecb: ciphertext length %d is not a multiple of block size %d", len(src), bs))
	}

	out := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		e.bc.DecryptBlock(out[i:i+bs], src[i:i+bs])
	}
	return padding.Unpad(out)
}