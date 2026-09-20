package padding

import "bytes"

func Pad(data []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("padding: blockSize must be in range [1, 255]")
	}
	p := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(p)}, p)
	return append(data, padText...)
}

func Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	p := int(data[len(data)-1])
	if p > len(data) {
		panic("padding: invalid padding")
	}
	return data[:len(data)-p]
}