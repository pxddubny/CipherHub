package sym

import (
	"bytes"
	"testing"
)

// Official belt-block test vectors from STB 34.101.31-2020, tables A.1 and A.2
// (source: http://apmi.bsu.by/assets/files/std/belt-spec371.pdf).
func TestBeltBlockKat(t *testing.T) {
	vectors := []struct {
		key []byte
		pt  []byte
		ct  []byte
	}{
		{
			key: mustHex(t, "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6"),
			pt:  mustHex(t, "B194BAC80A08F53B366D008E584A5DE4"),
			ct:  mustHex(t, "69CCA1C93557C9E3D66BC3E0FA88FA6E"),
		},
		{
			key: mustHex(t, "92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511"),
			pt:  mustHex(t, "0DC5300600CAB840B38448E5E993F421"),
			ct:  mustHex(t, "E12BDC1AE28257EC703FCCF095EE8DF1"),
		},
	}

	for i, tt := range vectors {
		m, err := NewBelt(tt.key)
		if err != nil {
			t.Fatalf("vector %d: NewBelt: %v", i, err)
		}

		enc := make([]byte, 16)
		m.EncryptBlock(enc, tt.pt)
		if !bytes.Equal(enc, tt.ct) {
			t.Errorf("vector %d: EncryptBlock = %x, want %x", i, enc, tt.ct)
		}

		dec := make([]byte, 16)
		m.DecryptBlock(dec, tt.ct)
		if !bytes.Equal(dec, tt.pt) {
			t.Errorf("vector %d: DecryptBlock = %x, want %x", i, dec, tt.pt)
		}
	}
}

func TestNewBeltKeyLengths(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		key := make([]byte, n)
		if _, err := NewBelt(key); err == nil {
			t.Errorf("NewBelt(len=%d): expected error, got nil", n)
		}
	}
	key := make([]byte, 32)
	b, err := NewBelt(key)
	if err != nil || b == nil {
		t.Fatalf("NewBelt(32 bytes): b=%v err=%v", b, err)
	}
}

func TestBeltBlockRoundTrip(t *testing.T) {
	key := mustHex(t, "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6")
	m, err := NewBelt(key)
	if err != nil {
		t.Fatalf("NewBelt: %v", err)
	}

	blocks := [][]byte{
		bytes.Repeat([]byte{0}, 16),
		bytes.Repeat([]byte{0xff}, 16),
		[]byte("0123456789abcdef"),
	}
	seed := uint32(0xdeadbeef)
	for i := 0; i < 16; i++ {
		b := make([]byte, 16)
		for j := range b {
			seed = seed*1664525 + 1013904223
			b[j] = byte(seed >> 24)
		}
		blocks = append(blocks, b)
	}

	enc := make([]byte, 16)
	dec := make([]byte, 16)
	for i, block := range blocks {
		m.EncryptBlock(enc, block)
		m.DecryptBlock(dec, enc)
		if !bytes.Equal(dec, block) {
			t.Errorf("block %d: round trip failed: got %x want %x", i, dec, block)
		}
	}
}

func TestBeltBlockTooShort(t *testing.T) {
	m, err := NewBelt(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewBelt: %v", err)
	}
	short := make([]byte, 15)
	dst := make([]byte, 16)

	expectPanic(t, "EncryptBlock short src", func() { m.EncryptBlock(dst, short) })
	expectPanic(t, "DecryptBlock short src", func() { m.DecryptBlock(dst, short) })
	expectPanic(t, "EncryptBlock short dst", func() { m.EncryptBlock(short, make([]byte, 16)) })
}

// Deterministic avalanche sanity check: single-bit flips must propagate.
func TestBeltAvalanche(t *testing.T) {
	key := mustHex(t, "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6")
	plain := mustHex(t, "B194BAC80A08F53B366D008E584A5DE4")

	m, err := NewBelt(key)
	if err != nil {
		t.Fatalf("NewBelt: %v", err)
	}
	base := make([]byte, 16)
	m.EncryptBlock(base, plain)

	totalBits := 0
	for i := 0; i < 128; i++ {
		flipped := append([]byte(nil), plain...)
		flipped[i/8] ^= 1 << uint(i%8)
		out := make([]byte, 16)
		m.EncryptBlock(out, flipped)
		if bytes.Equal(out, base) {
			t.Fatalf("plaintext bit %d flip left ciphertext unchanged", i)
		}
		totalBits += xorBits(base, out)
	}
	if totalBits < 1024 {
		t.Errorf("weak avalanche: %d bits changed over 128 flips, want >= 1024", totalBits)
	}
}
