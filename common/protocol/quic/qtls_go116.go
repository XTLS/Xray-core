//go:build go1.16 && !go1.17
// +build go1.16,!go1.17

package quic

import (
	"crypto/cipher"

	"github.com/marten-seemann/qtls-go1-16"
)

type (
	// A CipherSuiteTLS13 is a cipher suite for TLS 1.3
	CipherSuiteTLS13 = qtls.CipherSuiteTLS13
)

func AEADAESGCMTLS13(key, fixedNonce []byte) cipher.AEAD {
	return qtls.AEADAESGCMTLS13(key, fixedNonce)
}
