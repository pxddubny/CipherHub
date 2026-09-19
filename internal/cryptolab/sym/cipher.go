package sym

type BlockCipher interface {
    BlockSize() int
    EncryptBlock(dst, src []byte)
    DecryptBlock(dst, src []byte)
}

type Mode interface {
    Encrypt(src []byte) []byte
    Decrypt(src []byte) []byte
}