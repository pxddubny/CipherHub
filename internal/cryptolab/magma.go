package cryptolab

import (
	"encoding/binary"
	"fmt"
)

const (
	magmaBlockSize = 8
	magmaKeySize   = 32
)

var magmaSBox = [8][16]byte{
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
}

type Magma struct {
	subkeys [8]uint32
}

func NewMagma(key []byte) (*Magma, error) {
	if len(key) != magmaKeySize {
		return nil, fmt.Errorf("magma: key must be %d bytes, got %d", magmaKeySize, len(key))
	}

	m := &Magma{}
	for i := 0; i < 8; i++ {
		m.subkeys[i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}
	return m, nil
}

func (m *Magma) BlockSize() int { return magmaBlockSize }

func (m *Magma) EncryptBlock(dst, src []byte) {
	if len(src) < magmaBlockSize || len(dst) < magmaBlockSize {
		panic("magma: block too short")
	}

	n1 := binary.LittleEndian.Uint32(src[0:4])
	n2 := binary.LittleEndian.Uint32(src[4:8])

	round := [2]uint32{n1, n2}

	order := [32]int{
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
	}

	for i := 0; i < 32; i++ {
		round = magmaRound(round, m.subkeys[order[i]])
	}

	binary.LittleEndian.PutUint32(dst[0:4], round[1])
	binary.LittleEndian.PutUint32(dst[4:8], round[0])
}

func (m *Magma) DecryptBlock(dst, src []byte) {
	if len(src) < magmaBlockSize || len(dst) < magmaBlockSize {
		panic("magma: block too short")
	}

	n1 := binary.LittleEndian.Uint32(src[0:4])
	n2 := binary.LittleEndian.Uint32(src[4:8])

	round := [2]uint32{n1, n2}

	order := [32]int{
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
	}

	for i := 0; i < 32; i++ {
		round = magmaRound(round, m.subkeys[order[i]])
	}

	binary.LittleEndian.PutUint32(dst[0:4], round[1])
	binary.LittleEndian.PutUint32(dst[4:8], round[0])
}

func (m *Magma) GenerateMAC(data []byte) uint32 {
	padded := make([]byte, ((len(data)+7)/8)*8)
	copy(padded, data)

	var block [8]byte
	var buf [8]byte

	for i := 0; i < len(padded); i += 8 {
		for j := 0; j < 8; j++ {
			block[j] ^= padded[i+j]
		}

		m.EncryptBlock(buf[:], block[:])
		block = buf
	}

	return binary.LittleEndian.Uint32(block[0:4])
}

func magmaRound(block [2]uint32, key uint32) [2]uint32 {
	n1, n2 := block[0], block[1]

	sum := n2 + key
	sum = magmaSubstitute(sum)
	sum = rotLeft32(sum, 11)

	n1 ^= sum

	return [2]uint32{n2, n1}
}

func magmaSubstitute(x uint32) uint32 {
	var res uint32

	for i := 0; i < 8; i++ {
		val := byte((x >> (4 * i)) & 0xF)
		val = magmaSBox[i][val]
		res |= uint32(val) << (4 * i)
	}

	return res
}

func rotLeft32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}