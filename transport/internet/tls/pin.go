package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

func CalculatePEMCertChainSHA256Hash(certContent []byte) string {
	var certChain [][]byte
	for {
		block, remain := pem.Decode(certContent)
		if block == nil {
			break
		}
		certChain = append(certChain, block.Bytes)
		certContent = remain
	}
	certChainHash := GenerateCertChainHash(certChain)
	certChainHashB64 := base64.StdEncoding.EncodeToString(certChainHash)
	return certChainHashB64
}

func GenerateCertChainHash(rawCerts [][]byte) []byte {
	var hashValue []byte
	for _, certValue := range rawCerts {
		out := sha256.Sum256(certValue)
		if hashValue == nil {
			hashValue = out[:]
		} else {
			newHashValue := sha256.Sum256(append(hashValue, out[:]...))
			hashValue = newHashValue[:]
		}
	}
	return hashValue
}

func GenerateCertPublicKeyHash(cert *x509.Certificate) []byte {
	out := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return out[:]
}
