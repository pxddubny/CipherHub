package padding

import (
	"bytes"
	"strconv"
	"testing"
)

func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func TestPad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
	}{
		{"empty", nil, 8, bytes.Repeat([]byte{8}, 8)},
		{"shorter than block", []byte{0x01}, 8, append([]byte{0x01}, bytes.Repeat([]byte{7}, 7)...)},
		{"exact multiple", []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, bytes.Repeat([]byte{8}, 8)...)},
		{"one byte block", []byte{1, 2, 3}, 1, []byte{1, 2, 3, 1}},
		{"max block size", []byte{0}, 255, append([]byte{0}, bytes.Repeat([]byte{254}, 254)...)},
		{"full max block", bytes.Repeat([]byte{0xaa}, 255), 255, append(bytes.Repeat([]byte{0xaa}, 255), bytes.Repeat([]byte{255}, 255)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Pad(tt.data, tt.blockSize)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Pad(%v, %d) = %v, want %v", tt.data, tt.blockSize, got, tt.want)
			}
		})
	}
}

func TestPadInvalidBlockSize(t *testing.T) {
	for _, bs := range []int{0, -1, 256} {
		expectPanic(t, "Pad blockSize="+strconv.Itoa(bs), func() { Pad([]byte{1}, bs) })
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{"empty", nil, nil},
		{"one pad byte", []byte{0x01, 0x01}, []byte{0x01}},
		{"full block padding", []byte{8, 8, 8, 8, 8, 8, 8, 8}, nil},
		{"no padding marker", []byte{0x00}, []byte{0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Unpad(tt.data)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Unpad(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestUnpadInvalid(t *testing.T) {
	bad := [][]byte{
		{0x05},
		{0x02, 0xff},
		bytes.Repeat([]byte{9}, 8),
	}
	for i, data := range bad {
		expectPanic(t, "Unpad case "+strconv.Itoa(i), func() { Unpad(data) })
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	for _, bs := range []int{1, 2, 8, 16, 255} {
		for ln := 0; ln <= 257; ln++ {
			data := make([]byte, ln)
			for i := range data {
				data[i] = byte(i * 7)
			}
			got := Unpad(Pad(data, bs))
			if !bytes.Equal(got, data) {
				t.Fatalf("round trip failed: blockSize=%d len=%d\n got=%v\nwant=%v", bs, ln, got, data)
			}
		}
	}
}
