package quic

import (
	"crypto"
	"crypto/cipher"
	_ "crypto/tls"
	_ "unsafe"
)

// copied from github.com/quic-go/quic-go/internal/qtls/cipher_suite_go121.go

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

// github.com/quic-go/quic-go/internal/handshake/cipher_suite.go describes these cipher suite implementations are copied from the standard library crypto/tls package.
// So we can user go:linkname to implement the same feature.

//go:linkname aeadAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD
