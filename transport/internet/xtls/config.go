package xtls

import (
	"crypto/x509"
	"strings"
	"sync"
	"time"

	xtls "github.com/xtls/go"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	globalSessionCache = xtls.NewLRUClientSessionCache(128)
)

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool() (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if !root.AppendCertsFromPEM(cert.Certificate) {
			return nil, newError("failed to append cert").AtWarning()
		}
	}
	return root, nil
}

// BuildCertificates builds a list of TLS certificates from proto definition.
func (c *Config) BuildCertificates() []xtls.Certificate {
	certs := make([]xtls.Certificate, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		keyPair, err := xtls.X509KeyPair(entry.Certificate, entry.Key)
		if err != nil {
			newError("ignoring invalid X509 key pair").Base(err).AtWarning().WriteToLog()
			continue
		}
		certs = append(certs, keyPair)
		if entry.OcspStapling != 0 {
			go func(cert *xtls.Certificate) {
				t := time.NewTicker(time.Duration(entry.OcspStapling) * time.Second)
				for {
					if newData, err := ocsp.GetOCSPForCert(cert.Certificate); err != nil {
						newError("ignoring invalid OCSP").Base(err).AtWarning().WriteToLog()
					} else if string(newData) != string(cert.OCSPStaple) {
						cert.OCSPStaple = newData
					}
					<-t.C
				}
			}(&certs[len(certs)-1])
		}
	}
	return certs
}

func isCertificateExpired(c *xtls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(-time.Minute))
}

func issueCertificate(rawCA *Certificate, domain string) (*xtls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, newError("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, newError("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	cert, err := xtls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*Certificate {
	certs := make([]*Certificate, 0, len(c.Certificate))
	for _, certificate := range c.Certificate {
		if certificate.Usage == Certificate_AUTHORITY_ISSUE {
			certs = append(certs, certificate)
		}
	}
	return certs
}

func getGetCertificateFunc(c *xtls.Config, ca []*Certificate) func(hello *xtls.ClientHelloInfo) (*xtls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *xtls.ClientHelloInfo) (*xtls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]xtls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *xtls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					newError("failed to issue new certificate for ", domain).Base(err).WriteToLog()
					continue
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, newError("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func (c *Config) parseServerName() string {
	return c.ServerName
}

// GetXTLSConfig converts this Config into xtls.Config.
func (c *Config) GetXTLSConfig(opts ...Option) *xtls.Config {
	root, err := c.getCertPool()
	if err != nil {
		newError("failed to load system root certificate").AtError().Base(err).WriteToLog()
	}

	if c == nil {
		return &xtls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			InsecureSkipVerify:     false,
			NextProtos:             nil,
			SessionTicketsDisabled: false,
		}
	}

	config := &xtls.Config{
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		InsecureSkipVerify:     c.AllowInsecure,
		NextProtos:             c.NextProtocol,
		SessionTicketsDisabled: c.DisableSessionResumption,
	}

	for _, opt := range opts {
		opt(config)
	}

	config.Certificates = c.BuildCertificates()
	config.BuildNameToCertificate()

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = xtls.VersionTLS10
	case "1.1":
		config.MinVersion = xtls.VersionTLS11
	case "1.2":
		config.MinVersion = xtls.VersionTLS12
	case "1.3":
		config.MinVersion = xtls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = xtls.VersionTLS10
	case "1.1":
		config.MaxVersion = xtls.VersionTLS11
	case "1.2":
		config.MaxVersion = xtls.VersionTLS12
	case "1.3":
		config.MaxVersion = xtls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range xtls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, n := range strings.Split(c.CipherSuites, ":") {
			if id[n] != 0 {
				config.CipherSuites = append(config.CipherSuites, id[n])
			}
		}
	}

	config.PreferServerCipherSuites = c.PreferServerCipherSuites

	return config
}

// Option for building XTLS config.
type Option func(*xtls.Config)

// WithDestination sets the server name in XTLS config.
func WithDestination(dest net.Destination) Option {
	return func(config *xtls.Config) {
		if dest.Address.Family().IsDomain() && config.ServerName == "" {
			config.ServerName = dest.Address.Domain()
		}
	}
}

// WithNextProto sets the ALPN values in XTLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *xtls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}
