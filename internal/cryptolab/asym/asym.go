package asym

type PublicKey interface {
	Encrypt(plaintext []byte) ([]byte, error)
}

type PrivateKey interface {
	Decrypt(ciphertext []byte) ([]byte, error)
}