//go:build !windows
// +build !windows

package tls

import (
	"context"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"path/filepath"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type rootCertsCache struct {
	sync.Mutex
	pool *x509.CertPool
}

func (c *rootCertsCache) load() (*x509.CertPool, error) {
	c.Lock()
	defer c.Unlock()

	if c.pool != nil {
		return c.pool, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	intermediate_certs, err := loadIntermediateCerts()
	if err != nil {
		return nil, err
	}
	for _, cert := range intermediate_certs {
		pool.AddCert(cert)
	}
	c.pool = pool
	return pool, nil
}

var rootCerts rootCertsCache

func (c *Config) getCertPool() (*x509.CertPool, error) {
	if c.DisableSystemRoot {
		return c.loadSelfCertPool()
	}

	if len(c.Certificate) == 0 {
		return rootCerts.load()
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("system root").AtWarning().Base(err)
	}
	for _, cert := range c.Certificate {
		if !pool.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("append cert to root").AtWarning().Base(err)
		}
	}
	return pool, err
}

//go:embed intermediate_certs/*.crt
var certFiles embed.FS

func loadIntermediateCerts() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	entries, err := certFiles.ReadDir("intermediate_certs")
	if err != nil {
		return nil, errors.New("failed to read intermediate_certs")
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			content, err := certFiles.ReadFile(filepath.Join("intermediate_certs", entry.Name()))
			if err != nil {
				return nil, errors.New("failed to read intermediate cert for ", entry.Name())
			}

			block, _ := pem.Decode(content)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("failed to decode intermediate cert for ", entry.Name())
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("failed to parse intermediate cert for ", entry.Name())
			}

			if _, err := cert.Verify(x509.VerifyOptions{}); err != nil {
				errors.LogError(context.Background(), "failed to verify intermediate cert for ", entry.Name())
				continue
			}

			certs = append(certs, cert)
		}
	}

	return certs, nil
}
