package tls_test

import (
	gotls "crypto/tls"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

// The reload ticker invokes its first callback immediately, even without file
// paths or OCSP. Concurrent certificate selection must see immutable snapshots.
func TestCertificateSelectionDuringInitialReload(t *testing.T) {
	generated, err := cert.Generate(nil, cert.CommonName("example.com"), cert.DNSNames("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	certificate := ParseCertificate(generated)
	config := &Config{Certificate: []*Certificate{certificate}}
	for i := 0; i < 100; i++ {
		tlsConfig := config.GetTLSConfig()
		for j := 0; j < 50; j++ {
			selected, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{ServerName: "example.com"})
			if err != nil || selected == nil {
				t.Fatalf("certificate selection failed: %v", err)
			}
			_ = selected.Certificate[0]
			runtime.Gosched()
		}
	}
}
