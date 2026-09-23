package sym

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func expectPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func hexU32(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		t.Fatalf("bad uint32 hex %q: %v", s, err)
	}
	return uint32(v)
}

// magmaG is the round transformation f(k, a) = rotl11(t(a [+] k)): the
// right half plus the round subkey modulo 2^32, block substitution, then a
// cyclic shift by 11 bits to the left (ГОСТ 28147-89, раунд по описанию
// лабораторной работы).
func magmaG(k, a uint32) uint32 {
	return rotLeft32(magmaSubstitute(a+k), 11)
}

func TestNewMagmaKeyLengths(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		key := make([]byte, n)
		if _, err := NewMagma(key); err == nil {
			t.Errorf("NewMagma(len=%d): expected error, got nil", n)
		}
	}
	key := make([]byte, 32)
	m, err := NewMagma(key)
	if err != nil || m == nil {
		t.Fatalf("NewMagma(32 bytes): m=%v err=%v", m, err)
	}
}

// The 256-bit key is split little-endian into eight 32-bit subkeys
// (в lab: K0..K7 из 256-битного ключа).
func TestMagmaKeySchedule(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	want := []string{
		"ccddeeff", "8899aabb", "44556677", "00112233",
		"f3f2f1f0", "f7f6f5f4", "fbfaf9f8", "fffefdfc",
	}
	for i, w := range want {
		if got := m.subkeys[i]; got != hexU32(t, w) {
			t.Errorf("subkeys[%d] = %#08x, want %#08x", i, got, hexU32(t, w))
		}
	}
}

// Block substitution: each 4-bit block is replaced via the substitution
// table, S1 (the four low bits) first (opисание в лабораторной работе).
func TestMagmaSubstitution(t *testing.T) {
	tests := [][2]string{
		{"fdb97531", "c85af3ca"},
		{"4e516b79", "522c97ab"},
		{"5b9e6f7a", "776b9ba1"},
		{"3be0c80e", "07f6bee5"},
	}
	for _, tt := range tests {
		got := magmaSubstitute(hexU32(t, tt[0]))
		want := hexU32(t, tt[1])
		if got != want {
			t.Errorf("substitute(%s) = %#08x, want %#08x", tt[0], got, want)
		}
	}
}

// The round transformation: right half [+] subkey, substitution, rotl11.
func TestMagmaRoundFunction(t *testing.T) {
	tests := []struct{ k, a, want string }{
		{"87654321", "fedcba98", "e180dcab"},
		{"fdcbc20c", "87654321", "639a7cf8"},
		{"7e791a4b", "fdcbc20c", "a936f233"},
		{"c76549ec", "7e791a4b", "5cd672fe"},
	}
	for _, tt := range tests {
		got := magmaG(hexU32(t, tt.k), hexU32(t, tt.a))
		want := hexU32(t, tt.want)
		if got != want {
			t.Errorf("g[%s](%s) = %#08x, want %#08x", tt.k, tt.a, got, want)
		}
	}
}

func TestMagmaEncryptBlockKat(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	tests := []struct{ plain, want string }{
		{"fedcba9876543210", "9deeb1f79590f331"},
		{"0000000000000000", "8837578aee60f81c"},
		{"ffffffffffffffff", "5812edc0dbc374c6"},
	}
	for _, tt := range tests {
		got := make([]byte, 8)
		m.EncryptBlock(got, mustHex(t, tt.plain))
		if w := mustHex(t, tt.want); !bytes.Equal(got, w) {
			t.Errorf("EncryptBlock(%s) = %x, want %x", tt.plain, got, w)
		}
	}
}

func TestMagmaDecryptBlockKat(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	cipher := mustHex(t, "9deeb1f79590f331")
	want := mustHex(t, "fedcba9876543210")

	got := make([]byte, 8)
	m.DecryptBlock(got, cipher)
	if !bytes.Equal(got, want) {
		t.Errorf("DecryptBlock = %x, want %x", got, want)
	}
}

func TestMagmaBlockRoundTrip(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}

	blocks := [][]byte{
		bytes.Repeat([]byte{0}, 8),
		bytes.Repeat([]byte{0xff}, 8),
		{1, 2, 3, 4, 5, 6, 7, 8},
	}
	seed := uint32(0x12345678)
	for i := 0; i < 16; i++ {
		b := make([]byte, 8)
		for j := range b {
			seed = seed*1664525 + 1013904223
			b[j] = byte(seed >> 24)
		}
		blocks = append(blocks, b)
	}

	enc := make([]byte, 8)
	dec := make([]byte, 8)
	for i, block := range blocks {
		m.EncryptBlock(enc, block)
		m.DecryptBlock(dec, enc)
		if !bytes.Equal(dec, block) {
			t.Errorf("block %d: round trip failed: got %x want %x", i, dec, block)
		}
	}
}

func TestMagmaBlockTooShort(t *testing.T) {
	m, err := NewMagma(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	short := make([]byte, 7)
	dst := make([]byte, 8)

	expectPanic(t, "EncryptBlock short src", func() { m.EncryptBlock(dst, short) })
	expectPanic(t, "DecryptBlock short src", func() { m.DecryptBlock(dst, short) })
	expectPanic(t, "EncryptBlock short dst", func() { m.EncryptBlock(short, make([]byte, 8)) })
}

// Deterministic avalanche sanity check: flipping any single plaintext bit (or
// key bit) must change the ciphertext block.
func TestMagmaAvalanche(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	plain := mustHex(t, "fedcba9876543210")

	base := make([]byte, 8)
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	m.EncryptBlock(base, plain)

	totalBits := 0
	for i := 0; i < 64; i++ {
		flipped := append([]byte(nil), plain...)
		flipped[i/8] ^= 1 << uint(i%8)
		out := make([]byte, 8)
		m.EncryptBlock(out, flipped)
		if bytes.Equal(out, base) {
			t.Fatalf("plaintext bit %d flip left ciphertext unchanged", i)
		}
		totalBits += xorBits(base, out)
	}
	if totalBits < 512 {
		t.Errorf("weak avalanche: %d bits changed over 64 flips, want >= 512", totalBits)
	}

	keyFlipped := append([]byte(nil), key...)
	keyFlipped[0] ^= 1
	m2, err := NewMagma(keyFlipped)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	out := make([]byte, 8)
	m2.EncryptBlock(out, plain)
	if bytes.Equal(out, base) {
		t.Error("key bit flip left ciphertext unchanged")
	}
}

func xorBits(a, b []byte) int {
	n := 0
	for i := range a {
		v := a[i] ^ b[i]
		for v != 0 {
			n += int(v & 1)
			v >>= 1
		}
	}
	return n
}

func TestMagmaGenerateMAC(t *testing.T) {
	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	m, err := NewMagma(key)
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}

	data := []byte("magma mac test vector")
	again := []byte("magma mac test vector")
	other := []byte("magma mac test vectoo")

	if got, want := m.GenerateMAC(data), m.GenerateMAC(again); got != want {
		t.Errorf("MAC not deterministic: %#08x != %#08x", got, want)
	}
	if m.GenerateMAC(data) == m.GenerateMAC(other) {
		t.Error("different inputs produced equal MAC")
	}
	m2, err := NewMagma(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("NewMagma: %v", err)
	}
	if m.GenerateMAC(data) == m2.GenerateMAC(data) {
		t.Error("different keys produced equal MAC")
	}
}
