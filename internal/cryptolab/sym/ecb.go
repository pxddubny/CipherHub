package sym

import (
	"bytes"
	"fmt"
)

type ecb struct {
	bc BlockCipher
}

func NewECB(bc BlockCipher) Mode {
	return &ecb{bc: bc}
}

func (e *ecb) Encrypt(src []byte) []byte {
	bs := e.bc.BlockSize()
	padded := pkcs7Pad(src, bs)
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
	return pkcs7Unpad(out)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(data, padText...)
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	padding := int(data[len(data)-1])

	if padding > len(data) {
		panic("неверное дополнение")
	}

	return data[:len(data)-padding]
}