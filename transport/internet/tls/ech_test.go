package tls

import (
	"bytes"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

func newHTTPSRecord(name string, priority uint16, ttl uint32, target string, values ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(name),
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Priority: priority,
			Target:   dns.Fqdn(target),
			Value:    values,
		},
	}
}

func newMandatory(keys ...dns.SVCBKey) *dns.SVCBMandatory {
	return &dns.SVCBMandatory{Code: keys}
}

func newECHConfig(config []byte) *dns.SVCBECHConfig {
	return &dns.SVCBECHConfig{ECH: config}
}

func TestApplyECHInvalidForceQueryReturnsError(t *testing.T) {
	err := ApplyECH(&Config{
		EchConfigList: "AQI=",
		EchForceQuery: "broken",
	}, &gotls.Config{ServerName: "example.com"})
	if err == nil {
		t.Fatal("ApplyECH() expected error for invalid EchForceQuery")
	}
}

func TestECHCacheKeyUsesLogicalSocketConfig(t *testing.T) {
	left := &internet.SocketConfig{
		Mark:        100,
		DialerProxy: "proxy-tag",
		Interface:   "en0",
	}
	right := &internet.SocketConfig{
		Mark:        100,
		DialerProxy: "proxy-tag",
		Interface:   "en0",
	}
	different := &internet.SocketConfig{
		Mark:        101,
		DialerProxy: "proxy-tag",
		Interface:   "en0",
	}

	leftKey := ECHCacheKey("https://1.1.1.1/dns-query", "example.com", left)
	rightKey := ECHCacheKey("https://1.1.1.1/dns-query", "example.com", right)
	differentKey := ECHCacheKey("https://1.1.1.1/dns-query", "example.com", different)

	if leftKey != rightKey {
		t.Fatalf("ECHCacheKey() should be stable for logically equal sockopts: %q != %q", leftKey, rightKey)
	}
	if leftKey == differentKey {
		t.Fatalf("ECHCacheKey() should differ for different sockopts: %q == %q", leftKey, differentKey)
	}
}

func TestParseECHBootstrapServersRecognizesEncryptedResolvers(t *testing.T) {
	servers, err := parseECHBootstrapServers(" https://1.1.1.1/dns-query , tls://dns.google , udp://1.1.1.1 ")
	if err != nil {
		t.Fatalf("parseECHBootstrapServers() error = %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("parseECHBootstrapServers() len = %d, want 3", len(servers))
	}
	if !servers[0].encrypted {
		t.Fatal("parseECHBootstrapServers() should mark https resolver as encrypted")
	}
	if !servers[1].encrypted {
		t.Fatal("parseECHBootstrapServers() should mark tls resolver as encrypted")
	}
	if servers[2].encrypted {
		t.Fatal("parseECHBootstrapServers() should not mark udp resolver as encrypted")
	}
}

func TestQueryECHBootstrapServersPrefersEncryptedSuccess(t *testing.T) {
	encryptedConfig := []byte{0xEE}
	insecureConfig := []byte{0xAA}
	servers := []echBootstrapServer{
		{raw: "udp://1.1.1.1", encrypted: false},
		{raw: "https://1.1.1.1/dns-query", encrypted: true},
	}

	config, requireECH, ttl, err := queryECHBootstrapServers("example.com", "full", servers, func(server echBootstrapServer) ([]byte, bool, uint32, error) {
		switch server.raw {
		case "udp://1.1.1.1":
			return insecureConfig, false, 120, nil
		case "https://1.1.1.1/dns-query":
			time.Sleep(10 * time.Millisecond)
			return encryptedConfig, true, 30, nil
		default:
			return nil, false, 0, fmt.Errorf("unexpected server %s", server.raw)
		}
	})
	if err != nil {
		t.Fatalf("queryECHBootstrapServers() error = %v", err)
	}
	if !bytes.Equal(config, encryptedConfig) {
		t.Fatalf("queryECHBootstrapServers() config = %v, want %v", config, encryptedConfig)
	}
	if !requireECH {
		t.Fatal("queryECHBootstrapServers() should keep requireECH from the encrypted resolver")
	}
	if ttl != 30 {
		t.Fatalf("queryECHBootstrapServers() ttl = %d, want 30", ttl)
	}
}

func TestQueryECHBootstrapServersFullRejectsInsecureFallback(t *testing.T) {
	servers := []echBootstrapServer{
		{raw: "udp://1.1.1.1", encrypted: false},
		{raw: "https://1.1.1.1/dns-query", encrypted: true},
	}

	_, _, _, err := queryECHBootstrapServers("example.com", "full", servers, func(server echBootstrapServer) ([]byte, bool, uint32, error) {
		switch server.raw {
		case "udp://1.1.1.1":
			return []byte{0xAA}, false, 120, nil
		case "https://1.1.1.1/dns-query":
			return nil, false, 0, fmt.Errorf("doh failed")
		default:
			return nil, false, 0, fmt.Errorf("unexpected server %s", server.raw)
		}
	})
	if err == nil {
		t.Fatal("queryECHBootstrapServers() expected error when only insecure fallback succeeded in full mode")
	}
}

func TestQueryECHBootstrapServersFullKeepsLegacySingleUDP(t *testing.T) {
	expectedConfig := []byte{0xAA}
	servers := []echBootstrapServer{
		{raw: "udp://1.1.1.1", encrypted: false},
	}

	config, requireECH, ttl, err := queryECHBootstrapServers("example.com", "full", servers, func(server echBootstrapServer) ([]byte, bool, uint32, error) {
		return expectedConfig, false, 120, nil
	})
	if err != nil {
		t.Fatalf("queryECHBootstrapServers() error = %v", err)
	}
	if !bytes.Equal(config, expectedConfig) {
		t.Fatalf("queryECHBootstrapServers() config = %v, want %v", config, expectedConfig)
	}
	if requireECH {
		t.Fatal("queryECHBootstrapServers() unexpectedly required ECH for legacy udp-only bootstrap")
	}
	if ttl != 120 {
		t.Fatalf("queryECHBootstrapServers() ttl = %d, want 120", ttl)
	}
}

func TestResolveECHFromHTTPSLookupFollowsAliasAndKeepsOptionalFallback(t *testing.T) {
	expectedConfig := []byte{0x01, 0x02, 0x03}
	responses := map[string]*dns.Msg{
		"example.com.": {
			Answer: []dns.RR{
				newHTTPSRecord("example.com", 0, 120, "svc.example.com"),
			},
		},
		"svc.example.com.": {
			Answer: []dns.RR{
				newHTTPSRecord("svc.example.com", 1, 30, "."),
				newHTTPSRecord("svc.example.com", 2, 60, ".", newECHConfig(expectedConfig)),
			},
		},
	}

	config, requireECH, ttl, err := resolveECHFromHTTPSLookup("example.com", maxECHAliasDepth, map[string]struct{}{}, func(name string) (*dns.Msg, error) {
		msg, ok := responses[dns.Fqdn(name)]
		if !ok {
			return nil, fmt.Errorf("unexpected lookup for %s", name)
		}
		return msg, nil
	})
	if err != nil {
		t.Fatalf("resolveECHFromHTTPSLookup() error = %v", err)
	}
	if !bytes.Equal(config, expectedConfig) {
		t.Fatalf("resolveECHFromHTTPSLookup() config = %v, want %v", config, expectedConfig)
	}
	if requireECH {
		t.Fatal("resolveECHFromHTTPSLookup() unexpectedly required ECH when a compatible fallback endpoint exists")
	}
	if ttl != 30 {
		t.Fatalf("resolveECHFromHTTPSLookup() ttl = %d, want 30", ttl)
	}
}

func TestResolveECHFromHTTPSRRSetRejectsUnsupportedMandatoryParams(t *testing.T) {
	rejectedConfig := []byte{0x0A}
	selectedConfig := []byte{0x0B, 0x0C}
	rrset := []*dns.HTTPS{
		newHTTPSRecord("example.com", 1, 90, ".", newECHConfig(rejectedConfig), &dns.SVCBPort{Port: 8443}),
		newHTTPSRecord("example.com", 2, 45, ".", newECHConfig(selectedConfig), newMandatory(dns.SVCB_ECHCONFIG)),
	}

	config, requireECH, ttl, err := resolveECHFromHTTPSRRSet(rrset)
	if err != nil {
		t.Fatalf("resolveECHFromHTTPSRRSet() error = %v", err)
	}
	if !bytes.Equal(config, selectedConfig) {
		t.Fatalf("resolveECHFromHTTPSRRSet() config = %v, want %v", config, selectedConfig)
	}
	if !requireECH {
		t.Fatal("resolveECHFromHTTPSRRSet() should require ECH when every compatible record carries ech")
	}
	if ttl != 45 {
		t.Fatalf("resolveECHFromHTTPSRRSet() ttl = %d, want 45", ttl)
	}
}

func TestApplyECHFullAllowsFallbackWhenBootstrapIsOptional(t *testing.T) {
	GlobalECHConfigCache.Clear()
	t.Cleanup(func() {
		GlobalECHConfigCache.Clear()
	})

	cache := &ECHConfigCache{}
	cache.configRecord.Store(&echConfigRecord{
		expire: time.Now().Add(time.Minute),
	})
	GlobalECHConfigCache.Store(ECHCacheKey("udp://1.1.1.1", "example.com", nil), cache)

	tlsConfig := &gotls.Config{ServerName: "example.com"}
	err := ApplyECH(&Config{
		EchConfigList: "udp://1.1.1.1",
		EchForceQuery: "full",
	}, tlsConfig)
	if err != nil {
		t.Fatalf("ApplyECH() error = %v", err)
	}
	if len(tlsConfig.EncryptedClientHelloConfigList) != 0 {
		t.Fatalf("ApplyECH() forced an invalid config for an optional fallback path: %v", tlsConfig.EncryptedClientHelloConfigList)
	}
}

func TestApplyECHFullFailsWhenBootstrapRequiresECH(t *testing.T) {
	GlobalECHConfigCache.Clear()
	t.Cleanup(func() {
		GlobalECHConfigCache.Clear()
	})

	cache := &ECHConfigCache{}
	cache.configRecord.Store(&echConfigRecord{
		requireECH: true,
		expire:     time.Now().Add(time.Minute),
	})
	GlobalECHConfigCache.Store(ECHCacheKey("udp://1.1.1.1", "example.com", nil), cache)

	tlsConfig := &gotls.Config{ServerName: "example.com"}
	err := ApplyECH(&Config{
		EchConfigList: "udp://1.1.1.1",
		EchForceQuery: "full",
	}, tlsConfig)
	if err != nil {
		t.Fatalf("ApplyECH() error = %v", err)
	}
	expectedInvalid := []byte{1, 1, 4, 5, 1, 4}
	if !bytes.Equal(tlsConfig.EncryptedClientHelloConfigList, expectedInvalid) {
		t.Fatalf("ApplyECH() config = %v, want %v", tlsConfig.EncryptedClientHelloConfigList, expectedInvalid)
	}
}

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "encryptedsni.com+udp://1.1.1.1",
	}
	// test concurrent Dial(to test cache problem)
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Add(1)
		go func() {
			TLSConfig := config.GetTLSConfig()
			TLSConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: TLSConfig,
				},
			}
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
			common.Must(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			common.Must(err)
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("ECH Dial success but SNI is not encrypted")
			}
			wg.Done()
		}()
	}
	wg.Wait()
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load(ECHCacheKey("udp://1.1.1.1", "encryptedsni.com", nil))
	if !ok {
		t.Error("ECH config cache not found")

	}
	ok = echConfigCache.UpdateLock.TryLock()
	if !ok {
		t.Error("ECH config cache dead lock detected")
	}
	echConfigCache.UpdateLock.Unlock()
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
	}
}

func TestECHDialFail(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "udp://127.0.0.1",
		EchForceQuery: "half",
	}
	config.GetTLSConfig()
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load(ECHCacheKey("udp://127.0.0.1", "cloudflare.com", nil))
	if !ok {
		t.Error("ECH config cache not found")
	}
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
		return
	}
	if configRecord.err == nil {
		t.Error("unexpected nil error in ECH config record")
	}
}
