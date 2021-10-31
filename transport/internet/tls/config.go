package tls

import (
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

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
func (c *Config) BuildCertificates() []*tls.Certificate {
	certs := make([]*tls.Certificate, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		keyPair, err := tls.X509KeyPair(entry.Certificate, entry.Key)
		if err != nil {
			newError("ignoring invalid X509 key pair").Base(err).AtWarning().WriteToLog()
			continue
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			newError("ignoring invalid certificate").Base(err).AtWarning().WriteToLog()
			continue
		}
		certs = append(certs, &keyPair)
		if !entry.OneTimeLoading {
			var isOcspstapling bool
			hotReloadCertInterval := uint64(3600)
			if entry.OcspStapling != 0 {
				hotReloadCertInterval = entry.OcspStapling
				isOcspstapling = true
			}
			index := len(certs) - 1
			go func(entry *Certificate, cert *tls.Certificate, index int) {
				t := time.NewTicker(time.Duration(hotReloadCertInterval) * time.Second)
				for {
					if entry.CertificatePath != "" && entry.KeyPath != "" {
						newCert, err := filesystem.ReadFile(entry.CertificatePath)
						if err != nil {
							newError("failed to parse certificate").Base(err).AtError().WriteToLog()
							<-t.C
							continue
						}
						newKey, err := filesystem.ReadFile(entry.KeyPath)
						if err != nil {
							newError("failed to parse key").Base(err).AtError().WriteToLog()
							<-t.C
							continue
						}
						if string(newCert) != string(entry.Certificate) && string(newKey) != string(entry.Key) {
							newKeyPair, err := tls.X509KeyPair(newCert, newKey)
							if err != nil {
								newError("ignoring invalid X509 key pair").Base(err).AtError().WriteToLog()
								<-t.C
								continue
							}
							if newKeyPair.Leaf, err = x509.ParseCertificate(newKeyPair.Certificate[0]); err != nil {
								newError("ignoring invalid certificate").Base(err).AtError().WriteToLog()
								<-t.C
								continue
							}
							cert = &newKeyPair
						}
					}
					if isOcspstapling {
						if newOCSPData, err := ocsp.GetOCSPForCert(cert.Certificate); err != nil {
							newError("ignoring invalid OCSP").Base(err).AtWarning().WriteToLog()
						} else if string(newOCSPData) != string(cert.OCSPStaple) {
							cert.OCSPStaple = newOCSPData
						}
					}
					certs[index] = cert
					<-t.C
				}
			}(entry, certs[index], index)
		}
	}
	return certs
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, newError("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, newError("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
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

func getGetCertificateFunc(c *tls.Config, ca []*Certificate) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				} else if certificate.Leaf != nil {
					expTime := certificate.Leaf.NotAfter.Format(time.RFC3339)
					newError("old certificate for ", domain, " (expire on ", expTime, ") discarded").AtInfo().WriteToLog()
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					newError("failed to issue new certificate for ", domain).Base(err).WriteToLog()
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					newError("new certificate for ", domain, " (expire on ", expTime, ") issued").AtInfo().WriteToLog()
				} else {
					newError("failed to parse new certificate for ", domain).Base(err).WriteToLog()
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

func getNewGetCertificateFunc(certs []*tls.Certificate, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(certs) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
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

func (c *Config) parseServerName() string {
	return c.ServerName
}

func (c *Config) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.PinnedPeerCertificateChainSha256 != nil {
		hashValue := GenerateCertChainHash(rawCerts)
		for _, v := range c.PinnedPeerCertificateChainSha256 {
			if hmac.Equal(hashValue, v) {
				return nil
			}
		}
		return newError("peer cert is unrecognized: ", base64.StdEncoding.EncodeToString(hashValue))
	}
	return nil
}

// GetTLSConfig converts this Config into tls.Config.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		newError("failed to load system root certificate").AtError().Base(err).WriteToLog()
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			InsecureSkipVerify:     false,
			NextProtos:             nil,
			SessionTicketsDisabled: true,
		}
	}

	config := &tls.Config{
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		InsecureSkipVerify:     c.AllowInsecure,
		NextProtos:             c.NextProtocol,
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  c.verifyPeerCert,
	}

	for _, opt := range opts {
		opt(config)
	}

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(c.BuildCertificates(), c.RejectUnknownSni)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = tls.VersionTLS10
	case "1.1":
		config.MinVersion = tls.VersionTLS11
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = tls.VersionTLS10
	case "1.1":
		config.MaxVersion = tls.VersionTLS11
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
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

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if dest.Address.Family().IsDomain() && config.ServerName == "" {
			config.ServerName = dest.Address.Domain()
		}
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
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
