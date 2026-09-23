package sym

import (
	"bytes"
	"testing"
)

// xorCipher is a trivial self-inverse block "cipher" used to unit-test the
// mode logic (ECB padding, gamma/CFB feedback, length handling).
type xorCipher struct{ bs int }

func (x *xorCipher) BlockSize() int { return x.bs }
func (x *xorCipher) EncryptBlock(dst, src []byte) {
	for i := range src {
		dst[i] = src[i] ^ 0x5a
	}
}
func (x *xorCipher) DecryptBlock(dst, src []byte) {
	for i := range src {
		dst[i] = src[i] ^ 0x5a
	}
}

// newPRNG returns a simple deterministic LCG drawing bytes for payloads.
func newPRNG(seed uint32) func() uint32 {
	state := seed
	return func() uint32 {
		state = state*1664525 + 1013904223
		return state
	}
}

func testBlockCipher(t *testing.T, name string) BlockCipher {
	t.Helper()
	switch name {
	case "magma":
		m, err := NewMagma(mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
		if err != nil {
			t.Fatalf("NewMagma: %v", err)
		}
		return m
	case "belt":
		b, err := NewBelt(mustHex(t, "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6"))
		if err != nil {
			t.Fatalf("NewBelt: %v", err)
		}
		return b
	}
	t.Fatalf("unknown cipher %q", name)
	return nil
}

func testMode(t *testing.T, name string, bc BlockCipher) Mode {
	t.Helper()
	bs := bc.BlockSize()
	iv := make([]byte, bs)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	switch name {
	case "ecb":
		return NewECB(bc)
	case "gamma":
		m, err := NewGamma(bc, iv)
		if err != nil {
			t.Fatalf("NewGamma: %v", err)
		}
		return m
	case "cfb":
		m, err := NewCFB(bc, iv)
		if err != nil {
			t.Fatalf("NewCFB: %v", err)
		}
		return m
	}
	t.Fatalf("unknown mode %q", name)
	return nil
}

func testPayloads(bs int) [][]byte {
	payloads := [][]byte{
		{},
		{0x01},
		bytes.Repeat([]byte{0xab}, bs-1),
		bytes.Repeat([]byte{0xab}, bs),
		bytes.Repeat([]byte{0xab}, bs+1),
		bytes.Repeat([]byte{0x22}, 63),
		bytes.Repeat([]byte{0x22}, 64),
		bytes.Repeat([]byte{0x22}, 65),
		bytes.Repeat([]byte{0x22}, 1000),
	}
	prng := newPRNG(0x51f15e15)
	rand := make([]byte, 1009)
	for i := range rand {
		rand[i] = byte(prng() >> 24)
	}
	payloads = append(payloads, rand[:bs+31], rand[:1000], rand)
	return payloads
}

func TestModesRoundTrip(t *testing.T) {
	modeNames := []string{"ecb", "gamma", "cfb"}
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		bs := bc.BlockSize()
		for _, modeName := range modeNames {
			for _, payload := range testPayloads(bs) {
				m := testMode(t, modeName, bc)
				enc := m.Encrypt(payload)
				dec := m.Decrypt(enc)
				if !bytes.Equal(dec, payload) {
					t.Errorf("%s/%s len=%d: round trip failed: got %x want %x",
						cipherName, modeName, len(payload), dec, payload)
				}
				// gamma and cfb preserve length; ecb pads to a block multiple.
				if modeName == "gamma" || modeName == "cfb" {
					if len(enc) != len(payload) {
						t.Errorf("%s/%s len=%d: encrypted len %d, want %d",
							cipherName, modeName, len(payload), len(enc), len(payload))
					}
				} else {
					padded := (len(payload)/bs + 1) * bs
					if len(enc) != padded {
						t.Errorf("%s/ecb len=%d: encrypted len %d, want %d",
							cipherName, len(payload), len(enc), padded)
					}
				}
			}
		}
	}
}

func TestECBDeterministic(t *testing.T) {
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		m := testMode(t, "ecb", bc)
		a := m.Encrypt([]byte("deterministic"))
		b := m.Encrypt([]byte("deterministic"))
		if !bytes.Equal(a, b) {
			t.Errorf("%s: ECB not deterministic: %x != %x", cipherName, a, b)
		}
	}
}

func TestECBDecryptNonMultiplePanics(t *testing.T) {
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		m := testMode(t, "ecb", bc)
		for _, bad := range [][]byte{{0x01}, bytes.Repeat([]byte{0xaa}, bc.BlockSize()-1)} {
			bad := bad
			expectPanic(t, cipherName+" ecb decrypt length", func() { m.Decrypt(bad) })
		}
	}
}

func TestNewGammaIVSize(t *testing.T) {
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		for _, n := range []int{0, bc.BlockSize() - 1, bc.BlockSize() + 1} {
			if m, err := NewGamma(bc, make([]byte, n)); err == nil || m != nil {
				t.Errorf("%s: NewGamma(len(iv)=%d): expected error", cipherName, n)
			}
		}
	}
}

func TestNewCFBIVSize(t *testing.T) {
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		for _, n := range []int{0, bc.BlockSize() - 1, bc.BlockSize() + 1} {
			if m, err := NewCFB(bc, make([]byte, n)); err == nil || m != nil {
				t.Errorf("%s: NewCFB(len(iv)=%d): expected error", cipherName, n)
			}
		}
	}
}

// The IV passed to NewGamma/NewCFB must be copied: mutating it after
// construction must not change the produced keystream.
func TestModeIVCopied(t *testing.T) {
	for _, cipherName := range []string{"magma", "belt"} {
		bc := testBlockCipher(t, cipherName)
		payload := bytes.Repeat([]byte{0x42}, bc.BlockSize()*3+5)
		for _, modeName := range []string{"gamma", "cfb"} {
			iv := make([]byte, bc.BlockSize())
			for i := range iv {
				iv[i] = byte(i * 3)
			}
			m1, err := NewGamma(bc, iv)
			if modeName == "cfb" {
				m1, err = NewCFB(bc, iv)
			}
			if err != nil {
				t.Fatalf("%s/%s New: %v", cipherName, modeName, err)
			}
			before := m1.Encrypt(payload)

			iv[0] ^= 0xff
			iv[len(iv)-1] = 0

			after := m1.Encrypt(payload)
			if !bytes.Equal(before, after) {
				t.Errorf("%s/%s: IV not copied, mutation changed output", cipherName, modeName)
			}
		}
	}
}

// White-box checks of the mode logic against a trivial cipher.
func TestECBWithFakeCipher(t *testing.T) {
	bc := &xorCipher{bs: 2}
	m := NewECB(bc)
	pt := []byte{1, 2, 3, 4, 5} // 5 bytes -> padded to 6 by 1 byte of 0x01
	// 5 bytes -> padded to 6 by a byte of 0x01
	enc := m.Encrypt(pt)
	if len(enc) != 6 {
		t.Fatalf("Encrypt len = %d, want 6", len(enc))
	}
	want := append(append([]byte(nil), pt...), 0x01)
	for i, b := range enc {
		if b != want[i]^0x5a {
			t.Fatalf("enc[%d] = %#02x, want %#02x", i, b, want[i]^0x5a)
		}
	}
	if !bytes.Equal(m.Decrypt(enc), pt) {
		t.Fatal("ECB fake cipher round trip failed")
	}
}

func TestGammaWithFakeCipher(t *testing.T) {
	bc := &xorCipher{bs: 2}
	iv := []byte{0, 0}
	g, err := NewGamma(bc, iv)
	if err != nil {
		t.Fatalf("NewGamma: %v", err)
	}
	pt := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	enc := g.Encrypt(pt)
	if len(enc) != len(pt) {
		t.Fatalf("gamma Encrypt len = %d, want %d", len(enc), len(pt))
	}
	if !bytes.Equal(g.Decrypt(enc), pt) {
		t.Fatal("gamma fake cipher round trip failed")
	}
}

func TestCFBWithFakeCipher(t *testing.T) {
	bc := &xorCipher{bs: 2}
	iv := []byte{1, 2}
	c, err := NewCFB(bc, iv)
	if err != nil {
		t.Fatalf("NewCFB: %v", err)
	}
	pt := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	enc := c.Encrypt(pt)
	if len(enc) != len(pt) {
		t.Fatalf("cfb Encrypt len = %d, want %d", len(enc), len(pt))
	}
	if !bytes.Equal(c.Decrypt(enc), pt) {
		t.Fatal("cfb fake cipher round trip failed")
	}
}
