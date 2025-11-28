package hyutils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type LocalCertificateLoader struct {
	CertFile string
	KeyFile  string
	SNIGuard SNIGuardFunc

	lock  sync.Mutex
	cache atomic.Pointer[localCertificateCache]
}

type SNIGuardFunc func(info *tls.ClientHelloInfo, cert *tls.Certificate) error

// localCertificateCache holds the certificate and its mod times.
// this struct is designed to be read-only.
//
// to update the cache, use LocalCertificateLoader.makeCache and
// update the LocalCertificateLoader.cache field.
type localCertificateCache struct {
	certificate *tls.Certificate
	certModTime time.Time
	keyModTime  time.Time
}

func (l *LocalCertificateLoader) InitializeCache() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	cache, err := l.makeCache()
	if err != nil {
		return err
	}

	l.cache.Store(cache)
	return nil
}

func (l *LocalCertificateLoader) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := l.getCertificateWithCache()
	if err != nil {
		return nil, err
	}

	if l.SNIGuard == nil {
		return cert, nil
	}
	err = l.SNIGuard(info, cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (l *LocalCertificateLoader) checkModTime() (certModTime, keyModTime time.Time, err error) {
	fi, err := os.Stat(l.CertFile)
	if err != nil {
		err = fmt.Errorf("failed to stat certificate file: %w", err)
		return certModTime, keyModTime, err
	}
	certModTime = fi.ModTime()

	fi, err = os.Stat(l.KeyFile)
	if err != nil {
		err = fmt.Errorf("failed to stat key file: %w", err)
		return certModTime, keyModTime, err
	}
	keyModTime = fi.ModTime()
	return certModTime, keyModTime, err
}

func (l *LocalCertificateLoader) makeCache() (cache *localCertificateCache, err error) {
	c := &localCertificateCache{}

	c.certModTime, c.keyModTime, err = l.checkModTime()
	if err != nil {
		return cache, err
	}

	cert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
	if err != nil {
		return cache, err
	}
	c.certificate = &cert
	if c.certificate.Leaf == nil {
		// certificate.Leaf was left nil by tls.LoadX509KeyPair before Go 1.23
		c.certificate.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return cache, err
		}
	}

	cache = c
	return cache, err
}

func (l *LocalCertificateLoader) getCertificateWithCache() (*tls.Certificate, error) {
	cache := l.cache.Load()

	certModTime, keyModTime, terr := l.checkModTime()
	if terr != nil {
		if cache != nil {
			// use cache when file is temporarily unavailable
			return cache.certificate, nil
		}
		return nil, terr
	}

	if cache != nil && cache.certModTime.Equal(certModTime) && cache.keyModTime.Equal(keyModTime) {
		// cache is up-to-date
		return cache.certificate, nil
	}

	if cache != nil {
		if !l.lock.TryLock() {
			// another goroutine is updating the cache
			return cache.certificate, nil
		}
	} else {
		l.lock.Lock()
	}
	defer l.lock.Unlock()

	if l.cache.Load() != cache {
		// another goroutine updated the cache
		return l.cache.Load().certificate, nil
	}

	newCache, err := l.makeCache()
	if err != nil {
		if cache != nil {
			// use cache when loading failed
			return cache.certificate, nil
		}
		return nil, err
	}

	l.cache.Store(newCache)
	return newCache.certificate, nil
}

// getNameFromClientHello returns a normalized form of hello.ServerName.
// If hello.ServerName is empty (i.e. client did not use SNI), then the
// associated connection's local address is used to extract an IP address.
//
// ref: https://github.com/caddyserver/certmagic/blob/3bad5b6bb595b09c14bd86ff0b365d302faaf5e2/handshake.go#L838
func getNameFromClientHello(hello *tls.ClientHelloInfo) string {
	normalizedName := func(serverName string) string {
		return strings.ToLower(strings.TrimSpace(serverName))
	}
	localIPFromConn := func(c net.Conn) string {
		if c == nil {
			return ""
		}
		localAddr := c.LocalAddr().String()
		ip, _, err := net.SplitHostPort(localAddr)
		if err != nil {
			ip = localAddr
		}
		if scopeIDStart := strings.Index(ip, "%"); scopeIDStart > -1 {
			ip = ip[:scopeIDStart]
		}
		return ip
	}

	if name := normalizedName(hello.ServerName); name != "" {
		return name
	}
	return localIPFromConn(hello.Conn)
}

func SNIGuardDNSSAN(info *tls.ClientHelloInfo, cert *tls.Certificate) error {
	if len(cert.Leaf.DNSNames) == 0 {
		return nil
	}
	return SNIGuardStrict(info, cert)
}

func SNIGuardStrict(info *tls.ClientHelloInfo, cert *tls.Certificate) error {
	hostname := getNameFromClientHello(info)
	err := cert.Leaf.VerifyHostname(hostname)
	if err != nil {
		return fmt.Errorf("sni guard: %w", err)
	}
	return nil
}
