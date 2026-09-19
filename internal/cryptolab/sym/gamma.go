package sym

import (
	"fmt"
)

type gamma struct {
	bc  BlockCipher
	iv  []byte
}

func NewGamma(bc BlockCipher, iv []byte) (Mode, error) {
	if len(iv) != bc.BlockSize() {
		return nil, fmt.Errorf("gamma: iv must be %d bytes, got %d", bc.BlockSize(), len(iv))
	}
	cp := make([]byte, len(iv))
	copy(cp, iv)
	return &gamma{bc: bc, iv: cp}, nil
}

func (g *gamma) Encrypt(src []byte) []byte { return g.crypt(src) }
func (g *gamma) Decrypt(src []byte) []byte { return g.crypt(src) }

func (g *gamma) crypt(input []byte) []byte {
	bs := g.bc.BlockSize()
	out := make([]byte, len(input))

	state := make([]byte, bs)
	copy(state, g.iv)       // state = IV

	gammaBlock := make([]byte, bs)

	for i := 0; i < len(input); i += bs {
		g.bc.EncryptBlock(gammaBlock, state)

		remaining := len(input) - i
		if remaining > bs {
			remaining = bs
		}
		for j := 0; j < remaining; j++ {
			out[i+j] = input[i+j] ^ gammaBlock[j]
		}

		copy(state, gammaBlock)
	}

	return out
}