//go:build !windows
// +build !windows

package tls

import (
	"crypto/x509"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) getCertPool() (*x509.CertPool, error) {
	if c.DisableSystemRoot {
		return c.loadSelfCertPool()
	}

	if len(c.Certificate) == 0 {
		return loadCA(c.UseSystemCa), nil
	}

	pool := loadCA(c.UseSystemCa).Clone()
	for _, cert := range c.Certificate {
		if !pool.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("append cert to root")
		}
	}
	return pool, nil
}
