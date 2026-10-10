//go:build windows
// +build windows

package tls

import (
	"crypto/x509"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) getCertPool() (*x509.CertPool, error) {
	if c.DisableSystemRoot {
		return c.loadSelfCertPool()
	}

	// Windows should keep RootCAs nil for using the system CA.
	if c.UseSystemCa && len(c.Certificate) == 0 {
		return nil, nil
	}

	if len(c.Certificate) == 0 {
		return loadCA(c.UseSystemCa), nil
	}
	pool := loadCA(c.UseSystemCa).Clone()
	for _, cert := range c.Certificate {
		if !pool.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("failed to append cert")
		}
	}
	return pool, nil
}
