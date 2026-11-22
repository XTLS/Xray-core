package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestCertificateIssuing(t *testing.T) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestExpiredCertificate(t *testing.T) {
	caCert, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	expiredCert, _ := cert.MustGenerate(caCert, cert.NotAfter(time.Now().Add(time.Minute*-2)), cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))

	certificate := ParseCertificate(caCert)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	certificate2 := ParseCertificate(expiredCert)

	c := &Config{
		Certificate: []*Certificate{
			certificate,
			certificate2,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestInsecureCertificates(t *testing.T) {
	c := &Config{}

	tlsConfig := c.GetTLSConfig()
	if len(tlsConfig.CipherSuites) > 0 {
		t.Fatal("Unexpected tls cipher suites list: ", tlsConfig.CipherSuites)
	}
}

func BenchmarkCertificateIssuing(b *testing.B) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	lenCerts := len(tlsConfig.Certificates)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
			ServerName: "www.example.com",
		})
		delete(tlsConfig.NameToCertificate, "www.example.com")
		tlsConfig.Certificates = tlsConfig.Certificates[:lenCerts]
	}
}

// https://github.com/XTLS/Xray-core/issues/7398
func TestCertificateReloadDuringHandshakes(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert := func(domain string) {
		ct, _ := cert.MustGenerate(nil, cert.DNSNames(domain))
		certPEM, keyPEM := ct.ToPEM()
		common.Must(os.WriteFile(certPath, certPEM, 0o600))
		common.Must(os.WriteFile(keyPath, keyPEM, 0o600))
	}
	writeCert("a.example.com")
	certPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)

	c := &Config{Certificate: []*Certificate{{
		Certificate:     certPEM,
		Key:             keyPEM,
		CertificatePath: certPath,
		KeyPath:         keyPath,
		OcspStapling:    1, // reload every second
	}}}
	getCertificate := c.GetTLSConfig().GetCertificate
	writeCert("b.example.com")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		keyPair, err := getCertificate(&gotls.ClientHelloInfo{ServerName: "b.example.com"})
		common.Must(err)
		if keyPair.Leaf.DNSNames[0] == "b.example.com" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the reloaded certificate was never served")
}
