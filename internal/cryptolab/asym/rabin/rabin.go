package rabin

import (
	"errors"
	"math/big"

	"github.com/pxddubny/CipherHub/internal/padding"
)

const blockMarker = 0x02

type PublicKey struct {
	N *big.Int
}

func (k *PublicKey) Encrypt(plaintext []byte) ([]byte, error) {
	if k.N == nil || k.N.Sign() <= 0 {
		return nil, errors.New("rabin: invalid public key")
	}

	nBytes := (k.N.BitLen() + 7) / 8
	blockBytes := nBytes - 1
	if blockBytes < 1 {
		return nil, errors.New("rabin: key is too small")
	}
	dataBytes := blockBytes - 1
	if dataBytes < 1 {
		return nil, errors.New("rabin: key is too small for padding")
	}

	if len(plaintext) == 0 {
		return nil, nil
	}

	padded := padding.Pad(plaintext, dataBytes)

	out := make([]byte, 0, (len(padded)/dataBytes)*nBytes)
	for offset := 0; offset < len(padded); offset += dataBytes {
		block := padded[offset : offset+dataBytes]

		mBytes := make([]byte, nBytes)
		mBytes[0] = blockMarker
		copy(mBytes[1:], block)

		m := new(big.Int).SetBytes(mBytes)
		if m.Cmp(k.N) >= 0 {
			return nil, errors.New("rabin: block >= n; increase key size")
		}

		c := new(big.Int).Exp(m, big.NewInt(2), k.N)

		cBytes := c.FillBytes(make([]byte, nBytes))
		out = append(out, cBytes...)
	}

	return out, nil
}

type PrivateKey struct {
	Public PublicKey

	P  *big.Int
	Q  *big.Int
	Yp *big.Int
	Yq *big.Int
}

func (k *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if k.P == nil || k.Q == nil || k.Public.N == nil {
		return nil, errors.New("rabin: invalid private key")
	}
	if len(ciphertext) == 0 {
		return nil, nil
	}

	nBytes := (k.Public.N.BitLen() + 7) / 8
	blockBytes := nBytes - 1

	if len(ciphertext)%nBytes != 0 {
		return nil, errors.New("rabin: ciphertext length is not a multiple of block size")
	}

	var out []byte
	for offset := 0; offset < len(ciphertext); offset += nBytes {
		c := new(big.Int).SetBytes(ciphertext[offset : offset+nBytes])

		roots, err := k.squareRoots(c)
		if err != nil {
			return nil, err
		}

		block, err := selectBlock(roots, nBytes, blockBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}

	return out, nil
}

func (k *PrivateKey) squareRoots(c *big.Int) ([]*big.Int, error) {
	p, q, n := k.P, k.Q, k.Public.N

	if c.Cmp(n) >= 0 {
		return nil, errors.New("rabin: ciphertext block >= n")
	}

	expP := new(big.Int).Add(p, big.NewInt(1))
	expP.Rsh(expP, 2)
	mP := new(big.Int).Exp(c, expP, p)

	expQ := new(big.Int).Add(q, big.NewInt(1))
	expQ.Rsh(expQ, 2)
	mQ := new(big.Int).Exp(c, expQ, q)

	t1 := new(big.Int).Mul(k.Yp, p)
	t1.Mul(t1, mQ)

	t2 := new(big.Int).Mul(k.Yq, q)
	t2.Mul(t2, mP)

	r := new(big.Int).Add(t1, t2)
	r.Mod(r, n)

	negR := new(big.Int).Sub(n, r)
	if negR.Sign() == 0 || negR.Cmp(n) == 0 {
		negR.SetInt64(0)
	}

	s := new(big.Int).Sub(t1, t2)
	s.Mod(s, n)

	negS := new(big.Int).Sub(n, s)
	if negS.Sign() == 0 || negS.Cmp(n) == 0 {
		negS.SetInt64(0)
	}

	return []*big.Int{r, negR, s, negS}, nil
}

func selectBlock(roots []*big.Int, nBytes, blockBytes int) ([]byte, error) {
	for _, r := range roots {
		rBytes := r.FillBytes(make([]byte, nBytes))
		if rBytes[0] != blockMarker {
			continue
		}
		block := rBytes[1:]

		padLen := int(block[len(block)-1])
		if padLen == 0 || padLen > blockBytes {
			continue
		}
		valid := true
		for i := blockBytes - padLen; i < blockBytes; i++ {
			if block[i] != byte(padLen) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		return block[:blockBytes-padLen], nil
	}
	return nil, errors.New("rabin: no valid root found")
}