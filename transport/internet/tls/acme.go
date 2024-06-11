package tls

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// Start an ACME service
func StartACME(ACMEToken string, ACMEMail string, ServerName string) *certmagic.Config {
	if ACMEMail == "" {
		ACMEMail = "love@xray.com" // ¿
	}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	storage := certmagic.Default.Storage
	config := &certmagic.Config{
		DefaultServerName: ServerName,
		Storage:           storage,
	}
	var solver certmagic.DNS01Solver
	solver.DNSProvider = &cloudflare.Provider{
		APIToken: ACMEToken,
	}
	acmeConfig := certmagic.ACMEIssuer{
		CA:          certmagic.LetsEncryptProductionCA,
		Email:       ACMEMail,
		Agreed:      true,
		DNS01Solver: &solver,
	}

	config.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(config, acmeConfig)}
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certificate certmagic.Certificate) (*certmagic.Config, error) {
			return config, nil
		},
	})
	config = certmagic.New(cache, *config)

	err := config.ManageAsync(context.Background(), []string{ServerName})
	if err != nil {
		return nil
	}

	return config
}

// Get certificat
func GetACMECertificate(ACMEService *certmagic.Config, hello *tls.ClientHelloInfo) *tls.Certificate {
	cert, err := ACMEService.GetCertificate(hello)
	if err != nil {
		return nil
	}
	return cert
}


// An Option to change CertificateFunc to GetNewGetACMECertificateFunc()
func WithACME(rejectUnknownSNI bool, ACMEService *certmagic.Config) Option {
	return func(config *tls.Config) {
		config.GetCertificate = GetNewGetACMECertificateFunc(rejectUnknownSNI, ACMEService)
	}
}

func GetNewGetACMECertificateFunc(rejectUnknownSNI bool, ACMEService *certmagic.Config) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var certs []*tls.Certificate
		sni := strings.ToLower(hello.ServerName)
		certs = append(certs, GetACMECertificate(ACMEService, hello))
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		if !rejectUnknownSNI && (len(certs) == 1 || sni == "") {
			return certs[0], nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, keyPair := range certs {
			if keyPair.Leaf.Subject.CommonName == sni || keyPair.Leaf.Subject.CommonName == gsni {
				return keyPair, nil
			}
			for _, name := range keyPair.Leaf.DNSNames {
				if name == sni || name == gsni {
					return keyPair, nil
				}
			}
		}
		if rejectUnknownSNI {
			return nil, errNoCertificates
		}
		return certs[0], nil
	}
}