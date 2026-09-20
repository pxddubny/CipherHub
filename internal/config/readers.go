package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type keyReader interface {
	Read(size int, name string) ([]byte, error)
}

type argReader struct {
	value string
}

func (r *argReader) Read(size int, name string) ([]byte, error) {
	return parseHex(r.value, size, name)
}

type fileReader struct {
	path string
}

func (r *fileReader) Read(size int, name string) ([]byte, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read file %s: %w", name, r.path, err)
	}

	trimmed := strings.TrimSpace(string(data))

	if len(trimmed) == size*2 {
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s: file %s contains invalid hex: %w", name, r.path, err)
		}
		return decoded, nil
	}

	if len(data) == size {
		return data, nil
	}

	return nil, fmt.Errorf(
		"%s: file %s has unexpected size: got %d bytes, expected %d raw bytes or %d hex chars",
		name, r.path, len(data), size, size*2,
	)
}

type randReader struct {
	savePath string
}

func (r *randReader) Read(size int, name string) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("%s: failed to generate random data: %w", name, err)
	}

	if err := os.WriteFile(r.savePath, buf, 0600); err != nil {
		return nil, fmt.Errorf("%s: failed to write to %s: %w", name, r.savePath, err)
	}

	fmt.Fprintf(os.Stdout, "generated %s saved to %s (hex: %x)\n", name, r.savePath, buf)
	return buf, nil
}
