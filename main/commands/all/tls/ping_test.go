package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialTLSPingWithAlternateSNI(t *testing.T) {
	const acceptedName = "tenant.probe.invalid"
	certificate, leaf := makePingTestCertificate(t, acceptedName)
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		MinVersion:   gotls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tlsConn, ok := conn.(*gotls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(leaf)
	address := listener.Addr().(*net.TCPAddr)
	accepted, err := dialTLSPing(address, &gotls.Config{
		ServerName: acceptedName,
		RootCAs:    rootPool,
		MinVersion: gotls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("controlled alternate SNI should be accepted: %v", err)
	}
	accepted.Close()

	if _, err := dialTLSPing(address, &gotls.Config{
		ServerName: "unserved.probe.invalid",
		RootCAs:    rootPool,
		MinVersion: gotls.VersionTLS12,
	}); err == nil {
		t.Fatal("unserved SNI unexpectedly passed certificate verification")
	}
}

func TestAlternateSNIAssessmentIsLimited(t *testing.T) {
	accepted := alternateSNIAssessment("192.0.2.1:443", "tenant.example", nil)
	for _, text := range []string{"consistent with a shared TLS endpoint", "does not test", "does not prove"} {
		if !strings.Contains(accepted, text) {
			t.Fatalf("accepted assessment missing %q: %s", text, accepted)
		}
	}

	rejected := alternateSNIAssessment("192.0.2.1:443", "tenant.example", x509.HostnameError{})
	for _, text := range []string{"was not accepted", "does not prove"} {
		if !strings.Contains(rejected, text) {
			t.Fatalf("rejected assessment missing %q: %s", text, rejected)
		}
	}
}

func makePingTestCertificate(t *testing.T, name string) (gotls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}
