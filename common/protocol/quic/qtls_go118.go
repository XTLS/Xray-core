package quic

import (
	"crypto/cipher"
	_ "crypto/tls"
	_ "unsafe"
)

//go:linkname AEADAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func AEADAESGCMTLS13(key, nonceMask []byte) cipher.AEAD
