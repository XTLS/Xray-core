package xtls_test

import (
	"crypto/x509"
	"testing"
	"time"

	xtls "github.com/xtls/go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/xtls"
)

func TestCertificateIssuing(t *testing.T) {
	certificate := ParseCertificate(cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign)))
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	xtlsConfig := c.GetXTLSConfig()
	xrayCert, err := xtlsConfig.GetCertificate(&xtls.ClientHelloInfo{
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
	caCert := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	expiredCert := cert.MustGenerate(caCert, cert.NotAfter(time.Now().Add(time.Minute*-2)), cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))

	certificate := ParseCertificate(caCert)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	certificate2 := ParseCertificate(expiredCert)

	c := &Config{
		Certificate: []*Certificate{
			certificate,
			certificate2,
		},
	}

	xtlsConfig := c.GetXTLSConfig()
	xrayCert, err := xtlsConfig.GetCertificate(&xtls.ClientHelloInfo{
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

	xtlsConfig := c.GetXTLSConfig()
	if len(xtlsConfig.CipherSuites) > 0 {
		t.Fatal("Unexpected tls cipher suites list: ", xtlsConfig.CipherSuites)
	}
}

func BenchmarkCertificateIssuing(b *testing.B) {
	certificate := ParseCertificate(cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign)))
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	xtlsConfig := c.GetXTLSConfig()
	lenCerts := len(xtlsConfig.Certificates)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = xtlsConfig.GetCertificate(&xtls.ClientHelloInfo{
			ServerName: "www.example.com",
		})
		delete(xtlsConfig.NameToCertificate, "www.example.com")
		xtlsConfig.Certificates = xtlsConfig.Certificates[:lenCerts]
	}
}
