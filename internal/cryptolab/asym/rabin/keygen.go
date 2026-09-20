package rabin

import (
	"crypto/rand"
	"errors"
	"math/big"
)

func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < 16 {
		return nil, errors.New("rabin: bits must be at least 16")
	}

	half := bits / 2

	p, err := generatePrime3mod4(half)
	if err != nil {
		return nil, err
	}

	var q *big.Int
	for {
		q, err = generatePrime3mod4(half)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) != 0 {
			break
		}
	}

	n := new(big.Int).Mul(p, q)

	yp := new(big.Int)
	yq := new(big.Int)
	new(big.Int).GCD(yp, yq, p, q)

	return &PrivateKey{
		Public: PublicKey{N: n},
		P:      p,
		Q:      q,
		Yp:     yp,
		Yq:     yq,
	}, nil
}

func generatePrime3mod4(bits int) (*big.Int, error) {
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		if p.Bit(0) == 1 && p.Bit(1) == 1 {
			return p, nil
		}
	}
}