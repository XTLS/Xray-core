package tls

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

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

	// 管理证书 TODO
	err := config.ManageAsync(context.Background(), []string{ServerName})
	if err != nil {
		return nil
	}

	return config
}

func GetACMECertificate(ACMEService *certmagic.Config, hello *tls.ClientHelloInfo) *tls.Certificate {
	cert, err := ACMEService.GetCertificate(hello)
	if err != nil {
		return nil
	}
	return cert
}
