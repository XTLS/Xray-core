package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

func CalculatePEMLeafCertSHA256Hash(certContent []byte) (string, error) {
	var leafCert *x509.Certificate
	for {
		var err error
		block, remain := pem.Decode(certContent)
		if block == nil {
			break
		}
		leafCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		certContent = remain
	}
	certHash := GenerateCertHash(leafCert)
	certHashHex := hex.EncodeToString(certHash)
	return certHashHex, nil
}

// []byte must be ASN.1 DER content
func GenerateCertHash[T *x509.Certificate | []byte](cert T) []byte {
	var out [32]byte
	switch v := any(cert).(type) {
	case *x509.Certificate:
		out = sha256.Sum256(v.Raw)
	case []byte:
		out = sha256.Sum256(v)
	}
	return out[:]
}
