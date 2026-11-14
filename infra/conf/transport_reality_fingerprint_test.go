package conf

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	realitylib "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"
)

func realityWeightedTestConfig() *REALITYConfig {
	return &REALITYConfig{
		PublicKey:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ServerName: "example.com",
		ShortId:    "0123456789abcdef",
	}
}

func TestREALITYFingerprintWeightsBuild(t *testing.T) {
	c := realityWeightedTestConfig()
	c.FingerprintWeights = FingerprintWeights{"firefox": 9, "chrome": 70, "safari": 9}
	first, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	chosen := first.(*reality.Config).Fingerprint
	if _, ok := c.FingerprintWeights[chosen]; !ok {
		t.Fatalf("unexpected choice %q", chosen)
	}
	c.FingerprintWeights = FingerprintWeights{"Safari": 18, "Chrome": 140, "Firefox": 18}
	second, err := c.Build()
	if err != nil || !proto.Equal(first, second) {
		t.Fatalf("equivalent policy changed config: %v", err)
	}
	c.FingerprintWeights = nil
	c.Fingerprint = chosen
	single, err := c.Build()
	if err != nil || !proto.Equal(first, single) {
		t.Fatalf("weighted config differs from selected single profile: %v", err)
	}
}

func TestREALITYFingerprintWeightsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name        string
		weights     FingerprintWeights
		fingerprint string
		want        string
	}{
		{"empty", FingerprintWeights{}, "", "must not be empty"},
		{"conflict", FingerprintWeights{"chrome": 1}, "firefox", "mutually exclusive"},
		{"unknown", FingerprintWeights{"unknown": 1}, "", "unsupported"},
		{"random", FingerprintWeights{"random": 1}, "", "unsupported"},
		{"zero", FingerprintWeights{"chrome": 0}, "", "positive"},
		{"TLS12 candidate", FingerprintWeights{"chrome": 1000000, "hellochrome_58": 1}, "", "hellochrome_58"},
		{"old Edge", FingerprintWeights{"chrome": 70, "firefox": 9, "edge": 12, "safari": 9}, "", "X25519MLKEM768"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := realityWeightedTestConfig()
			c.FingerprintWeights, c.Fingerprint = tc.weights, tc.fingerprint
			if _, err := c.Build(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q error, got %v", tc.want, err)
			}
		})
	}
	for _, field := range []string{"target", "dest"} {
		var c REALITYConfig
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{%q:443,"fingerprintWeights":{"chrome":1}}`, field)), &c); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Build(); err == nil || !strings.Contains(err.Error(), "only supported in client") {
			t.Fatalf("server %s: %v", field, err)
		}
	}
}

func TestREALITYFingerprintWeightsLegacy(t *testing.T) {
	for _, name := range []string{"", "Firefox", "random", "randomized"} {
		c := realityWeightedTestConfig()
		c.Fingerprint = name
		built, err := c.Build()
		if err != nil {
			t.Fatal(err)
		}
		if got := built.(*reality.Config).Fingerprint; got != strings.ToLower(name) {
			t.Fatalf("legacy %q became %q", name, got)
		}
	}
}

func TestREALITYFingerprintWeightsNoSelectionOnInvalidConfig(t *testing.T) {
	w := FingerprintWeights{"chrome": 101, "firefox": 103}
	p, err := w.policy()
	if err != nil {
		t.Fatal(err)
	}
	c := realityWeightedTestConfig()
	c.FingerprintWeights, c.PublicKey = w, "invalid"
	if _, err := c.Build(); err == nil {
		t.Fatal("accepted invalid public key")
	}
	processFingerprints.mu.Lock()
	_, found := processFingerprints.choices[p.key]
	processFingerprints.mu.Unlock()
	if found {
		t.Fatal("invalid config selected a fingerprint")
	}
}

func TestREALITYFingerprintWeightsChecksCachedPolicies(t *testing.T) {
	// A generic TLS caller may have already resolved a policy containing an
	// older browser. REALITY must still validate every candidate on a cache hit.
	w := FingerprintWeights{"chrome": 107, "edge": 1}
	if _, err := w.Resolve(); err != nil {
		t.Fatal(err)
	}
	c := realityWeightedTestConfig()
	c.FingerprintWeights = w
	if _, err := c.Build(); err == nil || !strings.Contains(err.Error(), "X25519MLKEM768") {
		t.Fatalf("cached policy bypassed REALITY validation: %v", err)
	}
}

func TestREALITYFingerprintWeightsStreamTransports(t *testing.T) {
	for _, network := range []string{"raw", "xhttp", "grpc"} {
		t.Run(network, func(t *testing.T) {
			var c StreamConfig
			input := fmt.Sprintf(`{"network":%q,"security":"reality","realitySettings":{"publicKey":%q,"serverName":"example.com","fingerprintWeights":{"Firefox":9}}}`, network, realityWeightedTestConfig().PublicKey)
			if err := json.Unmarshal([]byte(input), &c); err != nil {
				t.Fatal(err)
			}
			built, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			memory, err := internet.ToMemoryStreamConfig(built)
			if err != nil {
				t.Fatal(err)
			}
			if got := reality.ConfigFromStreamSettings(memory).Fingerprint; got != "firefox" {
				t.Fatalf("runtime received %q", got)
			}
		})
	}
}

// Exercise the actual REALITY client/server against a local TLS 1.3 target.
// Each accepted current browser candidate must authenticate and carry data.
func TestREALITYFingerprintWeightsHandshake(t *testing.T) {
	target := httptest.NewUnstartedServer(nil)
	target.EnableHTTP2 = true
	target.TLS = &gotls.Config{MinVersion: gotls.VersionTLS13, CurvePreferences: []gotls.CurveID{gotls.X25519}}
	target.StartTLS()
	defer target.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := (&reality.Config{
		Dest: target.Listener.Addr().String(), Type: "tcp",
		PrivateKey: key.Bytes(), ServerNames: []string{"example.com"}, ShortIds: [][]byte{make([]byte, 8)},
	}).GetREALITYConfig()
	// Supply the known local target's empty post-handshake camouflage schedule;
	// production listeners populate this cache with target detection probes.
	for alpn := range 3 {
		cacheKey := fmt.Sprintf("%s example.com %d", serverConfig.Dest, alpn)
		realitylib.GlobalPostHandshakeRecordsLens.Store(cacheKey, []int{})
		defer realitylib.GlobalPostHandshakeRecordsLens.Delete(cacheKey)
	}
	for _, name := range []string{"chrome", "firefox", "safari"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(10 * time.Second))
				server, err := reality.Server(raw, serverConfig)
				if err != nil {
					finished <- err
					return
				}
				var data [4]byte
				if _, err = io.ReadFull(server, data[:]); err == nil {
					if string(data[:]) != "ping" {
						err = fmt.Errorf("unexpected application data %q", data)
					} else {
						_, err = server.Write([]byte("pong"))
					}
				}
				finished <- err
			}()
			c := realityWeightedTestConfig()
			c.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			c.ShortId = ""
			c.FingerprintWeights = FingerprintWeights{name: 1}
			built, err := c.Build()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := reality.UClient(raw, built.(*reality.Config), ctx, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
			if err != nil {
				t.Fatal(err)
			}
			if !client.(*reality.UConn).Verified {
				t.Fatal("REALITY authentication failed")
			}
			if _, err = client.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err = io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "pong" {
				t.Fatalf("application reply %q: %v", reply, err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}
