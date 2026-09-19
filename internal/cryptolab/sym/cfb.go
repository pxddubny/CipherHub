package sym

import (
	"fmt"
)

type cfb struct {
	bc BlockCipher
	iv []byte
}

func NewCFB(bc BlockCipher, iv []byte) (Mode, error) {
	if len(iv) != bc.BlockSize() {
		return nil, fmt.Errorf("cfb: iv must be %d bytes, got %d", bc.BlockSize(), len(iv))
	}
	cp := make([]byte, len(iv))
	copy(cp, iv)
	return &cfb{bc: bc, iv: cp}, nil
}

func (c *cfb) Encrypt(src []byte) []byte {
	bs := c.bc.BlockSize()
	out := make([]byte, len(src))

	feedback := make([]byte, bs)
	copy(feedback, c.iv)

	gamma := make([]byte, bs)
	cipherBlock := make([]byte, bs)

	for i := 0; i < len(src); i += bs {
		c.bc.EncryptBlock(gamma, feedback)

		remaining := len(src) - i
		if remaining > bs {
			remaining = bs
		}

		for j := 0; j < remaining; j++ {
			cipherBlock[j] = src[i+j] ^ gamma[j]
			out[i+j] = cipherBlock[j]
		}

		copy(feedback, cipherBlock[:remaining])
	}

	return out
}

func (c *cfb) Decrypt(src []byte) []byte {
	bs := c.bc.BlockSize()
	out := make([]byte, len(src))

	feedback := make([]byte, bs)
	copy(feedback, c.iv)

	gamma := make([]byte, bs)
	cipherBlock := make([]byte, bs)

	for i := 0; i < len(src); i += bs {
		c.bc.EncryptBlock(gamma, feedback)

		remaining := len(src) - i
		if remaining > bs {
			remaining = bs
		}

		for j := 0; j < remaining; j++ {
			cipherBlock[j] = src[i+j]
			out[i+j] = src[i+j] ^ gamma[j]
		}

		copy(feedback, cipherBlock[:remaining])
	}

	return out
}