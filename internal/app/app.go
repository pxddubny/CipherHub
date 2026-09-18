package app

import (
	"io"
	"os"

	"github.com/pxddubny/CipherHub/internal/config"
	"github.com/pxddubny/CipherHub/internal/cryptolab"
)

func Run(cfg *config.Config) (*uint32, error) {
	plain, err := readFile(cfg.Input)
	if err != nil {
		return nil, err
	}

	var result []byte
	switch {
	case cfg.Mode == "encrypt" && cfg.Algorithm == "ecb":
		ecb := cryptolab.NewECB(cfg.BlockCipher)
		result = ecb.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "ecb":
		ecb := cryptolab.NewECB(cfg.BlockCipher)
		result = ecb.Decrypt(plain)

	case cfg.Mode == "encrypt" && cfg.Algorithm == "gamma":
		gamma, err := cryptolab.NewGamma(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = gamma.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "gamma":
		gamma, err := cryptolab.NewGamma(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = gamma.Decrypt(plain)

	case cfg.Mode == "encrypt" && cfg.Algorithm == "cfb":
		cfb, err := cryptolab.NewCFB(cfg.BlockCipher, cfg.Iv)
		if err != nil {
			return nil, err
		}
		result = cfb.Encrypt(plain)

	case cfg.Mode == "decrypt" && cfg.Algorithm == "cfb":
		cfb, err := cryptolab.NewCFB(cfg.BlockCipher, cfg.Iv)
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
				return &mac, err
    }
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