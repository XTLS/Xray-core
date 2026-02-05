package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/xtls/xray-core/common/errors"
)

func CalculatePEMLeafCertSHA256Hash(certContent []byte) (string, error) {
	for {
		block, remain := pem.Decode(certContent)
		if block == nil {
			return "", errors.New("Unable to decode cert")
		}
		Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		if !Cert.IsCA {
			certHash := GenerateCertHash(Cert)
			certHashHex := hex.EncodeToString(certHash)
			return certHashHex, nil
		}
		certContent = remain
	}
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
