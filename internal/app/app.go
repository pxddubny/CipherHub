package app

import (
	"errors"
	"io"
	"os"

	"github.com/pxddubny/CipherHub/internal/config"
	"github.com/pxddubny/CipherHub/internal/cryptolab/sym"
)

func Run(cfg *config.Config) (*uint32, error) {
	switch cfg.Family {
	case config.FamilySym:
		return runSym(cfg)
	case config.FamilyAsym:
		return runAsym(cfg)
	default:
		return nil, errors.New("unknown crypto family: " + string(cfg.Family))
	}
}

func runSym(cfg *config.Config) (*uint32, error) {
	plain, err := readFile(cfg.Input)
	if err != nil {
		return nil, err
	}

	var result []byte
	switch {
	case cfg.Mode == "encrypt" && cfg.Algorithm == "ecb":
		ecb := sym.NewECB(cfg.BlockCipher)
		result = ecb.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "ecb":
		ecb := sym.NewECB(cfg.BlockCipher)
		result = ecb.Decrypt(plain)

	case cfg.Mode == "encrypt" && cfg.Algorithm == "gamma":
		gamma, err := sym.NewGamma(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = gamma.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "gamma":
		gamma, err := sym.NewGamma(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = gamma.Decrypt(plain)

	case cfg.Mode == "encrypt" && cfg.Algorithm == "cfb":
		cfb, err := sym.NewCFB(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = cfb.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "cfb":
		cfb, err := sym.NewCFB(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = cfb.Decrypt(plain)
	}

	if err := writeFile(cfg.Output, result); err != nil {
		return nil, err
	}

	if cfg.MAC {
		if m, ok := cfg.BlockCipher.(interface{ GenerateMAC([]byte) uint32 }); ok {
			var mac uint32
			if cfg.Mode == "encrypt" {
				mac = m.GenerateMAC(plain)
			} else {
				mac = m.GenerateMAC(result)
			}
			return &mac, nil
		}
	}

	return nil, nil
}

func runAsym(cfg *config.Config) (*uint32, error) {
	data, err := readFile(cfg.Input)
	if err != nil {
		return nil, err
	}

	var result []byte
	switch cfg.Mode {
	case "encrypt":
		if cfg.PublicKey == nil {
			return nil, errors.New("encryption requires a public key")
		}
		result, err = cfg.PublicKey.Encrypt(data)
	case "decrypt":
		if cfg.PrivateKey == nil {
			return nil, errors.New("decryption requires a private key")
		}
		result, err = cfg.PrivateKey.Decrypt(data)
	}
	if err != nil {
		return nil, err
	}

	if err := writeFile(cfg.Output, result); err != nil {
		return nil, err
	}

	return nil, nil
}

func readFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	return io.ReadAll(f)
}

func writeFile(name string, data []byte) error {
	return os.WriteFile(name, data, 0644)
}
