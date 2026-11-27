package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
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

// Handshakes read the certificate while it is reloaded from disk; run with -race.
func TestCertificateHotReload(t *testing.T) {
	old, _ := cert.MustGenerate(nil, cert.CommonName("old.example.com"))
	certificate := ParseCertificate(old)
	dir := t.TempDir()
	certificate.CertificatePath = filepath.Join(dir, "cert.pem")
	certificate.KeyPath = filepath.Join(dir, "key.pem")
	// The reload goroutine reads the files at once, before its first tick.
	ct, _ := cert.MustGenerate(nil, cert.CommonName("new.example.com"))
	certPEM, keyPEM := ct.ToPEM()
	common.Must(os.WriteFile(certificate.CertificatePath, certPEM, 0o600))
	common.Must(os.WriteFile(certificate.KeyPath, keyPEM, 0o600))
	getCertificate := (&Config{Certificate: []*Certificate{certificate}}).GetTLSConfig().GetCertificate

	waitCertificate(t, getCertificate, func(keyPair *gotls.Certificate) bool {
		return keyPair.Leaf.Subject.CommonName == "new.example.com"
	})
}

// An OCSP update must not change the certificate that a handshake may still hold; run with -race.
func TestCertificateOCSPUpdate(t *testing.T) {
	responses := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, responses.Add(1))
	}))
	defer server.Close()
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	leaf, _ := cert.MustGenerate(ca, cert.CommonName("example.com"), func(c *x509.Certificate) {
		c.OCSPServer = []string{server.URL}
	})
	certificate := ParseCertificate(leaf)
	caPEM, _ := ca.ToPEM()
	certificate.Certificate = append(certificate.Certificate, caPEM...)
	certificate.OcspStapling = 1 // The OCSP update interval, in seconds.
	getCertificate := (&Config{Certificate: []*Certificate{certificate}}).GetTLSConfig().GetCertificate

	stapled := func(previous string) func(*gotls.Certificate) bool {
		return func(keyPair *gotls.Certificate) bool {
			return len(keyPair.OCSPStaple) > 0 && string(keyPair.OCSPStaple) != previous
		}
	}
	first := waitCertificate(t, getCertificate, stapled(""))
	staple := string(first.OCSPStaple)
	waitCertificate(t, getCertificate, stapled(staple))
	if string(first.OCSPStaple) != staple {
		t.Fatal("OCSP update changed the certificate in use: ", staple, " -> ", string(first.OCSPStaple))
	}
}

// waitCertificate polls getCertificate for up to 5 seconds until it returns a matching certificate.
func waitCertificate(t *testing.T, getCertificate func(*gotls.ClientHelloInfo) (*gotls.Certificate, error), match func(*gotls.Certificate) bool) *gotls.Certificate {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		keyPair, err := getCertificate(&gotls.ClientHelloInfo{})
		common.Must(err)
		if match(keyPair) {
			return keyPair
		}
	}
	t.Fatal("certificate is not updated")
	return nil
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
