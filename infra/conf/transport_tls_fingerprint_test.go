package conf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func TestTLSFingerprintWeightsBuild(t *testing.T) {
	c := &TLSConfig{ServerName: "example.com", FingerprintWeights: FingerprintWeights{"firefox": 9, "chrome": 70, "edge": 12, "safari": 9}}
	first, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	chosen := first.(*tls.Config).Fingerprint
	if _, ok := c.FingerprintWeights[chosen]; !ok {
		t.Fatalf("unexpected choice %q", chosen)
	}
	c.FingerprintWeights = FingerprintWeights{"Safari": 18, "EDGE": 24, "Chrome": 140, "Firefox": 18}
	second, err := c.Build()
	if err != nil || !proto.Equal(first, second) {
		t.Fatalf("equivalent policy changed config: %v", err)
	}
	c.FingerprintWeights, c.Fingerprint = nil, chosen
	single, err := c.Build()
	if err != nil || !proto.Equal(first, single) {
		t.Fatalf("differs from legacy selected profile: %v", err)
	}
}

func TestTLSFingerprintWeightsValidation(t *testing.T) {
	for _, input := range []string{
		`{"fingerprintWeights":{}}`,
		`{"fingerprint":"chrome","fingerprintWeights":{"firefox":1}}`,
		`{"fingerprintWeights":{"chrome":0}}`,
		`{"fingerprintWeights":{"unknown":1}}`,
		`{"fingerprintWeights":{"random":1}}`,
		`{"fingerprintWeights":{"chrome":-1}}`,
		`{"fingerprintWeights":{"chrome":1.2}}`,
	} {
		var c TLSConfig
		if err := json.Unmarshal([]byte(input), &c); err != nil {
			continue
		}
		if _, err := c.Build(); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, name := range []string{"", "Firefox", "random", "randomized", "unsafe", "hellogolang"} {
		built, err := (&TLSConfig{Fingerprint: name}).Build()
		if err != nil {
			t.Fatal(err)
		}
		if got := built.(*tls.Config).Fingerprint; got != strings.ToLower(name) {
			t.Fatalf("legacy %q became %q", name, got)
		}
	}
	w := FingerprintWeights{"chrome": 109, "firefox": 113}
	p, err := w.policy()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&TLSConfig{FingerprintWeights: w, PinnedPeerCertSha256: "bad"}).Build(); err == nil {
		t.Fatal("accepted invalid certificate pin")
	}
	processFingerprints.mu.Lock()
	_, found := processFingerprints.choices[p.key]
	processFingerprints.mu.Unlock()
	if found {
		t.Fatal("invalid TLS config selected a fingerprint")
	}
}

func TestTLSFingerprintWeightsTransports(t *testing.T) {
	for _, tc := range []struct {
		network, alpn string
		valid         bool
	}{
		{"raw", `null`, true}, {"grpc", `null`, true}, {"ws", `null`, true},
		{"httpupgrade", `null`, true}, {"xhttp", `["h2"]`, true}, {"xdrive", `null`, true},
		{"masque", `["h2"]`, true}, {"masque", `["h2","http/1.1"]`, true},
		{"masque", `null`, false}, {"masque", `["h2","h3"]`, false},
		{"xhttp", `["h3"]`, false}, {"xdrive", `["h3"]`, false},
		{"xhttp", `["h3","h2"]`, true}, {"xdrive", `["h3","h2"]`, true},
		{"hysteria", `null`, false}, {"kcp", `null`, false},
	} {
		t.Run(tc.network+tc.alpn, func(t *testing.T) {
			var c StreamConfig
			input := fmt.Sprintf(`{"network":%q,"security":"tls","tlsSettings":{"alpn":%s,"fingerprintWeights":{"Firefox":1}}}`, tc.network, tc.alpn)
			if err := json.Unmarshal([]byte(input), &c); err != nil {
				t.Fatal(err)
			}
			built, err := c.Build()
			if !tc.valid {
				if err == nil || !strings.Contains(err.Error(), "fingerprintWeights") {
					t.Fatalf("want unsupported policy error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			memory, err := internet.ToMemoryStreamConfig(built)
			if err != nil {
				t.Fatal(err)
			}
			if got := tls.ConfigFromStreamSettings(memory).Fingerprint; got != "firefox" {
				t.Fatalf("runtime received %q", got)
			}
		})
	}
}

func TestTLSFingerprintWeightsBrowserDialer(t *testing.T) {
	t.Setenv("xray.browser.dialer", "127.0.0.1:0")
	for _, network := range []string{"websocket", "splithttp"} {
		c := &TLSConfig{FingerprintWeights: FingerprintWeights{"chrome": 1}}
		if err := c.validateFingerprintTransport(network); err == nil || !strings.Contains(err.Error(), "browser") {
			t.Fatalf("%s: %v", network, err)
		}
		c.FingerprintWeights = nil
		if err := c.validateFingerprintTransport(network); err != nil {
			t.Fatalf("legacy affected: %v", err)
		}
	}
}

func TestTLSFingerprintWeightsNestedResolvers(t *testing.T) {
	for _, tc := range []struct {
		addr, alpn string
		valid      bool
	}{
		{"https://example.com/dns-query", "h2", true},
		{"https://example.com/dns-query", "h3", false},
		{"tcp://127.0.0.1", "h2", false}, {"127.0.0.1", "h2", false},
	} {
		alpn := StringList{tc.alpn}
		c := &XDNS{Resolvers: []XDNSResolver{{Addrs: []string{tc.addr}, TlsConfig: &TLSConfig{ALPN: &alpn, FingerprintWeights: FingerprintWeights{"safari": 1}}}}}
		built, err := c.Build()
		if !tc.valid {
			if err == nil || !strings.Contains(err.Error(), "fingerprintWeights") {
				t.Fatalf("%s/%s: %v", tc.addr, tc.alpn, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := built.(*xdns.Config).Resolvers[0].TlsConfig.Fingerprint; got != "safari" {
			t.Fatalf("nested resolver received %q", got)
		}
	}
	if _, err := (&Realm{TlsConfig: &TLSConfig{FingerprintWeights: FingerprintWeights{"chrome": 1}}}).Build(); err == nil || !strings.Contains(err.Error(), "Go TLS") {
		t.Fatalf("Realm: %v", err)
	}
}

func TestTLSFingerprintWeightsHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pong") }))
	defer server.Close()
	hash := sha256.Sum256(server.Certificate().Raw)
	for _, name := range []string{"chrome", "firefox", "edge", "safari"} {
		t.Run(name, func(t *testing.T) {
			c := &TLSConfig{ServerName: "example.com", PinnedPeerCertSha256: hex.EncodeToString(hash[:]), FingerprintWeights: FingerprintWeights{name: 1}}
			built, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			config := built.(*tls.Config)
			// Reuse the built configuration on two independent TCP connections.
			for range 2 {
				raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.UClient(raw, config.GetTLSConfig(), tls.GetFingerprint(config.Fingerprint)).(*tls.UConn)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err = conn.HandshakeContext(ctx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if conn.ClientHelloID.Client != tls.GetFingerprint(name).Client || conn.ClientHelloID.Version != tls.GetFingerprint(name).Version {
					t.Fatal("wrong runtime fingerprint")
				}
				request, err := http.NewRequest("GET", server.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Close = true
				if err := request.Write(conn); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				raw.Close()
				if err != nil || string(body) != "pong" {
					t.Fatalf("reply %q: %v", body, err)
				}
			}
		})
	}
}
