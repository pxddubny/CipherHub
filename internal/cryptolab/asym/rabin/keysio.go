package rabin

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

var privateKeyFields = []string{"n", "p", "q", "yp", "yq"}

const (
	privKeyFileMode = 0600
	pubKeyFileMode  = 0644
)

func (k *PublicKey) Save(path string) error {
	if k == nil || k.N == nil || k.N.Sign() <= 0 {
		return errors.New("rabin: cannot save an empty public key")
	}
	return writeBigInts(path, map[string]*big.Int{"n": k.N}, pubKeyFileMode)
}

func (k *PrivateKey) Save(path string) error {
	if k == nil || k.Public.N == nil || k.P == nil || k.Q == nil || k.Yp == nil || k.Yq == nil {
		return errors.New("rabin: cannot save an empty private key")
	}
	return writeBigInts(path, map[string]*big.Int{
		"n":  k.Public.N,
		"p":  k.P,
		"q":  k.Q,
		"yp": k.Yp,
		"yq": k.Yq,
	}, privKeyFileMode)
}

func LoadPublicKey(path string) (*PublicKey, error) {
	values, err := readBigInts(path, []string{"n"})
	if err != nil {
		return nil, err
	}
	if values["n"].Sign() <= 0 {
		return nil, fmt.Errorf("rabin: %s: non-positive modulus n", path)
	}
	return &PublicKey{N: values["n"]}, nil
}

func LoadPrivateKey(path string) (*PrivateKey, error) {
	values, err := readBigInts(path, privateKeyFields)
	if err != nil {
		return nil, err
	}

	k := &PrivateKey{
		Public: PublicKey{N: values["n"]},
		P:      values["p"],
		Q:      values["q"],
		Yp:     values["yp"],
		Yq:     values["yq"],
	}

	if k.P.Sign() <= 0 || k.Q.Sign() <= 0 || k.Public.N.Sign() <= 0 {
		return nil, fmt.Errorf("rabin: %s: modulus and primes must be positive", path)
	}

	check := new(big.Int).Mul(k.Yp, k.P)
	check.Add(check, new(big.Int).Mul(k.Yq, k.Q))
	if check.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("rabin: %s: invalid key file: yp*p + yq*q != 1", path)
	}

	return k, nil
}

func writeBigInts(path string, fields map[string]*big.Int, mode os.FileMode) error {
	var b strings.Builder
	for _, name := range privateKeyFields {
		v, ok := fields[name]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "%s=%s\n", name, v.Text(16))
	}
	return os.WriteFile(path, []byte(b.String()), mode)
}

func readBigInts(path string, names []string) (map[string]*big.Int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	values := make(map[string]*big.Int, len(names))
	found := make(map[string]bool, len(names))
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v, ok := new(big.Int).SetString(strings.TrimSpace(value), 16)
		if !ok {
			return nil, fmt.Errorf("rabin: %s: invalid number", path)
		}
		values[name] = v
		found[name] = true
	}

	for _, name := range names {
		if !found[name] {
			return nil, fmt.Errorf("rabin: %s: missing field %s", path, name)
		}
	}

	return values, nil
}
