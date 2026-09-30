package masque

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	WarpHost = "cloudflareaccess.com"
	WarpPath = "/"
)

func warpCertificate(der []byte) (*gotls.Certificate, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("invalid WARP private key").Base(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the WARP private key is not an ECDSA key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &gotls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}, nil
}

func useWarp(config *Config, tlsConfig *gotls.Config) error {
	if config.Warp == nil {
		return nil
	}
	cert, err := warpCertificate(config.Warp.PrivateKey)
	if err != nil {
		return err
	}
	tlsConfig.GetClientCertificate = func(*gotls.CertificateRequestInfo) (*gotls.Certificate, error) {
		return cert, nil
	}
	if publicKey := config.Warp.PublicKey; len(publicKey) > 0 {
		verify := tlsConfig.VerifyPeerCertificate
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the WARP endpoint sent no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, publicKey) {
				return errors.New("the WARP endpoint's key doesn't match \"publicKey\"")
			}
			if verify != nil {
				return verify(raw, chains)
			}
			return nil
		}
	}
	return nil
}
