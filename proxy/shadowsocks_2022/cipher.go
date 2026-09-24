package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherMethod struct {
	Name          string
	KeySaltLength int
	IsChaCha      bool
}

var (
	cipherAES128GCM        = &CipherMethod{Name: MethodAES128GCM, KeySaltLength: 16, IsChaCha: false}
	cipherAES256GCM        = &CipherMethod{Name: MethodAES256GCM, KeySaltLength: 32, IsChaCha: false}
	cipherChaCha20Poly1305 = &CipherMethod{Name: MethodChaCha20Poly1305, KeySaltLength: 32, IsChaCha: true}
)

func GetCipherMethod(name string) (*CipherMethod, error) {
	switch name {
	case MethodAES128GCM:
		return cipherAES128GCM, nil
	case MethodAES256GCM:
		return cipherAES256GCM, nil
	case MethodChaCha20Poly1305:
		return cipherChaCha20Poly1305, nil
	default:
		return nil, errors.New("unknown shadowsocks 2022 method")
	}
}

// NewAEAD creates standard stream AEAD cipher instance (AES-GCM or ChaCha20-Poly1305)
func (m *CipherMethod) NewAEAD(key []byte) (cipher.AEAD, error) {
	if m.IsChaCha {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewBlock creates standard 16-byte block cipher for AES header encryption/decryption
func (m *CipherMethod) NewBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// NewUDPCipher creates AEAD cipher for UDP packets (XChaCha20-Poly1305 with 24-byte nonce)
func (m *CipherMethod) NewUDPCipher(key []byte) (cipher.AEAD, error) {
	if m.IsChaCha {
		return chacha20poly1305.NewX(key)
	}
	return nil, errors.New("shadowsocks-2022: udp separate AEAD cipher only available for chacha20 method")
}
