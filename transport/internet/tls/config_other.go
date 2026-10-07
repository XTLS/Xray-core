//go:build !windows
// +build !windows

package tls

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// androidSystemCertDir is the location of the system CA store on Android.
// Binaries built with GOOS=linux (as the official releases are) only search
// /etc/ssl/certs and /etc/pki/tls/certs for system roots, none of which exist
// on Android, so they end up with an empty root pool and fail to verify any
// certificate chain. Fall back to the Android store in that case.
const androidSystemCertDir = "/system/etc/security/cacerts"

func loadSystemCertPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || (pool != nil && len(pool.Subjects()) > 0) {
		return pool, err
	}
	if runtime.GOOS == "linux" {
		if p := loadCertsFromDir(androidSystemCertDir); p != nil {
			return p, nil
		}
	}
	return pool, err
}

func loadCertsFromDir(dir string) *x509.CertPool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			pool.AppendCertsFromPEM(data)
		}
	}
	if len(pool.Subjects()) == 0 {
		return nil
	}
	return pool
}

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

	pool, err := loadSystemCertPool()
	if err != nil {
		return nil, err
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

	pool, err := loadSystemCertPool()
	if err != nil {
		return nil, errors.New("system root").Base(err)
	}
	for _, cert := range c.Certificate {
		if !pool.AppendCertsFromPEM(cert.Certificate) {
			return nil, errors.New("append cert to root").Base(err)
		}
	}
	return pool, nil
}
