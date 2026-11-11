package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

func peerCommonName(serverConfig *gotls.Config) (string, error) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	deadline := time.Now().Add(5 * time.Second)
	serverSide.SetDeadline(deadline)
	clientSide.SetDeadline(deadline)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- gotls.Server(serverSide, serverConfig).Handshake()
	}()
	client := gotls.Client(clientSide, &gotls.Config{InsecureSkipVerify: true})
	if err := client.Handshake(); err != nil {
		return "", err
	}
	if err := <-serverErr; err != nil {
		return "", err
	}
	return client.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
}

func TestCertificateReloadDuringHandshakes(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write := func(cn string) {
		c, _ := cert.MustGenerate(nil, cert.CommonName(cn))
		certPEM, keyPEM := c.ToPEM()
		common.Must(os.WriteFile(certFile, certPEM, 0o600))
		common.Must(os.WriteFile(keyFile, keyPEM, 0o600))
	}
	write("first")
	certPEM := common.Must2(os.ReadFile(certFile))
	keyPEM := common.Must2(os.ReadFile(keyFile))

	config := (&Config{Certificate: []*Certificate{{
		Certificate: certPEM, Key: keyPEM, CertificatePath: certFile, KeyPath: keyFile, OcspStapling: 1,
	}}}).GetTLSConfig()

	var sawSecond atomic.Bool
	stop := make(chan struct{})
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				name, err := peerCommonName(config)
				if err != nil {
					t.Error(err)
					return
				}
				if name == "second" {
					sawSecond.Store(true)
				}
			}
		}()
	}

	write("second")
	deadline := time.Now().Add(10 * time.Second)
	for !sawSecond.Load() && !t.Failed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	workers.Wait()
	if !sawSecond.Load() {
		t.Error("handshakes never saw the reloaded certificate")
	}
}

func TestOCSPUpdateCopiesCertificate(t *testing.T) {
	var responses atomic.Int64
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "staple-%d", responses.Add(1))
	}))
	defer responder.Close()

	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.CommonName("Test CA"), cert.KeyUsage(x509.KeyUsageCertSign))
	leaf, _ := cert.MustGenerate(ca, cert.CommonName("leaf"), func(c *x509.Certificate) {
		c.OCSPServer = []string{responder.URL}
	})
	leafPEM, keyPEM := leaf.ToPEM()
	caPEM, _ := ca.ToPEM()

	config := (&Config{Certificate: []*Certificate{{
		Certificate: append(leafPEM, caPEM...), Key: keyPEM, OcspStapling: 1,
	}}}).GetTLSConfig()
	current := func() *gotls.Certificate {
		return common.Must2(config.GetCertificate(&gotls.ClientHelloInfo{}))
	}

	waitFor := func(what string, done func(*gotls.Certificate) bool) *gotls.Certificate {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			c := current()
			if done(c) {
				return c
			}
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for ", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	first := waitFor("the first staple", func(c *gotls.Certificate) bool { return len(c.OCSPStaple) > 0 })
	firstStaple := string(first.OCSPStaple)
	updated := waitFor("a new staple", func(c *gotls.Certificate) bool { return string(c.OCSPStaple) != firstStaple })

	if updated == first {
		t.Error("the OCSP update reused the published certificate")
	}
	if got := string(first.OCSPStaple); got != firstStaple {
		t.Errorf("published certificate changed its staple from %q to %q", firstStaple, got)
	}
}
