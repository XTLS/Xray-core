package conf

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestXDNSResolverEncryptedAddresses(t *testing.T) {
	for _, tc := range []struct{ input, protocol, address string }{
		{"127.0.0.1", "udp", "127.0.0.1:53"},
		{"tcp://[::1]", "tcp", "[::1]:53"},
		{"tls://resolver.test", "tls", "resolver.test:853"},
		{"quic://resolver.test", "quic", "resolver.test:853"},
		{"https://resolver.test/custom?name=one", "https", "https://resolver.test:443/custom?name=one"},
		{"https+h3://resolver.test", "https+h3", "https://resolver.test:443/dns-query"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			built, err := (&XDNS{Resolvers: []XDNSResolver{{Addrs: []string{tc.input}}}}).Build()
			if err != nil {
				t.Fatal(err)
			}
			r := built.(*xdns.Config).Resolvers[0]
			if r.Type != tc.protocol || r.Addr != tc.address {
				t.Fatalf("got %s %s; want %s %s", r.Type, r.Addr, tc.protocol, tc.address)
			}
		})
	}
}

func buildXDNSMaskJSON(document string) (*xdns.Config, error) {
	settings := json.RawMessage(document)
	built, err := (&Mask{Type: "xdns", Settings: &settings}).Build(false)
	if err != nil {
		return nil, err
	}
	return built.(*xdns.Config), nil
}

func TestXDNSJSONRejectsInvalidResolverAddress(t *testing.T) {
	for _, address := range []string{
		"https://resolver.test:/", "https://resolver.test/#", "https+h3://resolver.test:/", "https+h3://resolver.test/#",
		"https://[::1]:/", "https://[::1]/#", "tls://resolver.test:", "quic://resolver.test/#", "127.0.0.1:", "udp://resolver.test/#",
		"", "https:///dns-query", "https://:443/dns-query", "https://resolver.test:0/", "https://resolver.test:65536/", "https://resolver.test:invalid/",
		"https://resolver.test:-1/", "https://u:p@resolver.test/", "https://@resolver.test/", "https://resolver.test/#fragment", "https://resolver.test/path?token=x#fragment",
		"https://[resolver.test]/", "https://[127.0.0.1]/", "https://::1/", "https://::1:443/", "https://[::1/", "https://resolver.test/%zz", "http://resolver.test/dns-query",
		"tcp://resolver.test/path", "udp://resolver.test?query=x", "tls://resolver.test/", "quic://resolver.test?", "quic://resolver.test:53",
	} {
		t.Run(address, func(t *testing.T) {
			document := `{"resolvers":[{"addrs":[` + strconv.Quote(address) + `]}]}`
			var decoded XDNS
			if err := json.Unmarshal([]byte(document), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Resolvers[0].Addrs[0] != address {
				t.Fatal("JSON decode changed original resolver address")
			}
			if _, err := buildXDNSMaskJSON(document); err == nil {
				t.Fatal("JSON/Build accepted an invalid resolver address")
			}
		})
	}
}

func TestXDNSJSONResolverAddresses(t *testing.T) {
	for _, tc := range []struct{ address, protocol, want string }{
		{"127.0.0.1", "udp", "127.0.0.1:53"},
		{"[::1]", "udp", "[::1]:53"},
		{"udp://resolver.test:5353", "udp", "resolver.test:5353"},
		{"tcp://resolver.test", "tcp", "resolver.test:53"},
		{"tcp://[::1]:5353", "tcp", "[::1]:5353"},
		{"tls://resolver.test", "tls", "resolver.test:853"},
		{"tls://[::1]:8853", "tls", "[::1]:8853"},
		{"quic://resolver.test", "quic", "resolver.test:853"},
		{"quic://[::1]:8853", "quic", "[::1]:8853"},
		{"https://resolver.test", "https", "https://resolver.test:443/dns-query"},
		{"https+h3://resolver.test", "https+h3", "https://resolver.test:443/dns-query"},
		{"https://[::1]", "https", "https://[::1]:443/dns-query"},
		{"https+h3://[::1]:8443/dns-query", "https+h3", "https://[::1]:8443/dns-query"},
		{"https://resolver.test/dns%2Dquery?token=a%2Fb&x=1&x=2&tag=%23", "https", "https://resolver.test:443/dns%2Dquery?token=a%2Fb&x=1&x=2&tag=%23"},
		{"https+h3://resolver.test:8443/custom%2Fpath?z=last&a=first&a=second", "https+h3", "https://resolver.test:8443/custom%2Fpath?z=last&a=first&a=second"},
		{"https://resolver.test/custom?", "https", "https://resolver.test:443/custom?"},
		{"https://resolver.test/?token=a", "https", "https://resolver.test:443/?token=a"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			document := `{"resolvers":[{"addrs":[` + strconv.Quote(tc.address) + `]}]}`
			built, err := buildXDNSMaskJSON(document)
			if err != nil {
				t.Fatal(err)
			}
			if len(built.Resolvers) != 1 || built.Resolvers[0].Type != tc.protocol || built.Resolvers[0].Addr != tc.want {
				t.Fatalf("JSON/Build changed resolver semantics: %+v", built.Resolvers)
			}
		})
	}
}

func TestXDNSJSONRejectsResolverOptions(t *testing.T) {
	for _, group := range []string{
		`{"addrs":["https://resolver.test"],"serverName":"other.test"}`,
		`{"addrs":["https+h3://resolver.test"],"serverName":"other.test"}`,
		`{"addrs":["tls://resolver.test"],"serverName":"resolver.test:853"}`,
		`{"addrs":["quic://resolver.test"],"serverName":"bad name"}`,
		`{"addrs":["tls://resolver.test"],"serverName":"https://resolver.test"}`,
		`{"addrs":["https://resolver.test"],"bootstrap":"bootstrap.test"}`,
		`{"addrs":["https://resolver.test"],"bootstrap":"127.0.0.1:443"}`,
		`{"addrs":["https://resolver.test"],"bootstrap":"127.0.0.1,127.0.0.2"}`,
		`{"addrs":["https://resolver.test"],"bootstrap":"127.0.0.0/24"}`,
		`{"addrs":["https://resolver.test"],"bootstrap":"[::1]"}`,
		`{"addrs":["udp://resolver.test"],"serverName":"resolver.test"}`,
		`{"addrs":["tcp://resolver.test"],"bootstrap":"127.0.0.1"}`,
		`{"addrs":["https://resolver.test","udp://resolver.test"],"bootstrap":"127.0.0.1"}`,
		`{"addrs":["https://resolver.test"],"certificates":[null]}`,
		`{"addrs":["https://resolver.test"],"certificates":[{"usage":"verify","certificate":["not PEM"]}]}`,
	} {
		t.Run(group, func(t *testing.T) {
			if _, err := buildXDNSMaskJSON(`{"resolvers":[` + group + `]}`); err == nil {
				t.Fatal("JSON/Build accepted invalid resolver options")
			}
		})
	}
}

func TestXDNSJSONResolverIdentityAndBootstrap(t *testing.T) {
	for _, tc := range []struct{ address, identity, bootstrap string }{
		{"tls://127.0.0.1", "resolver.test", "::1"},
		{"quic://127.0.0.1", "resolver.test", "127.0.0.2"},
		{"https://resolver.test", "RESOLVER.TEST", "127.0.0.1"},
		{"https+h3://[::1]", "::1", "127.0.0.1"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			document := `{"resolvers":[{"addrs":[` + strconv.Quote(tc.address) + `],"serverName":` + strconv.Quote(tc.identity) + `,"bootstrap":` + strconv.Quote(tc.bootstrap) + `}]}`
			built, err := buildXDNSMaskJSON(document)
			if err != nil {
				t.Fatal(err)
			}
			r := built.Resolvers[0]
			if r.ServerName != tc.identity || r.Bootstrap != tc.bootstrap {
				t.Fatalf("identity/bootstrap were changed: %+v", r)
			}
		})
	}
}

func xdnsTestResolverWireFields(t *testing.T, wire []byte) map[protowire.Number][]byte {
	t.Helper()
	fields := make(map[protowire.Number][]byte)
	for len(wire) != 0 {
		number, typ, n := protowire.ConsumeTag(wire)
		if n < 0 || typ != protowire.BytesType {
			t.Fatal("invalid resolver protobuf field")
		}
		wire = wire[n:]
		value, n := protowire.ConsumeBytes(wire)
		if n < 0 {
			t.Fatal("invalid resolver protobuf value")
		}
		fields[number] = value
		wire = wire[n:]
	}
	return fields
}

func TestXDNSResolverLegacyProtoCompatibility(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		wire     []byte
	}{
		{"udp", []byte("\x0a\x03udp\x12\x0c127.0.0.1:53")},
		{"tcp", []byte("\x0a\x03tcp\x12\x0c127.0.0.1:53")},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			var decoded xdns.ResolverProto
			if err := proto.Unmarshal(tc.wire, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Type != tc.protocol || decoded.Addr != "127.0.0.1:53" || decoded.ServerName != "" || decoded.Bootstrap != "" || len(decoded.Certificates) != 0 {
				t.Fatalf("old field 1/2 wire data changed: %+v", &decoded)
			}
			encoded, err := proto.Marshal(&decoded)
			if err != nil {
				t.Fatal(err)
			}
			fields := xdnsTestResolverWireFields(t, encoded)
			if string(fields[1]) != tc.protocol || string(fields[2]) != "127.0.0.1:53" {
				t.Fatal("old protobuf field numbers changed")
			}
		})
	}
}

func TestXDNSJSONProtoRoundTrip(t *testing.T) {
	authority, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	rootPEM, _ := authority.ToPEM()
	document, err := json.Marshal(&XDNS{
		Domains: []XDNSDomain{{Names: []string{"tunnel.example"}, LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 1232}},
		Resolvers: []XDNSResolver{{
			Addrs:      []string{"https+h3://resolver.test/custom%2Fpath?token=a%2Fb&x=1&x=2"},
			ServerName: "resolver.test", Bootstrap: "127.0.0.1",
			Certificates: []*TLSCertConfig{{Usage: "verify", CertStr: strings.Split(strings.TrimSpace(string(rootPEM)), "\n")}},
		}},
		ExtraPoll: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	built, err := buildXDNSMaskJSON(string(document))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	var decoded xdns.Config
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ExtraPoll != 2 || len(decoded.Domains) != 1 || decoded.Domains[0].Name != "tunnel.example" || decoded.Domains[0].Edns0 != 1232 || len(decoded.Resolvers) != 1 {
		t.Fatalf("config proto round trip lost fields: %+v", &decoded)
	}
	r := decoded.Resolvers[0]
	const wantURL = "https://resolver.test:443/custom%2Fpath?token=a%2Fb&x=1&x=2"
	if r.Type != "https+h3" || r.Addr != wantURL || r.ServerName != "resolver.test" || r.Bootstrap != "127.0.0.1" {
		t.Fatalf("resolver proto round trip lost fields: %+v", r)
	}
	if len(r.Certificates) != 1 || r.Certificates[0].Usage != xtls.Certificate_AUTHORITY_VERIFY || !bytes.Equal(r.Certificates[0].Certificate, bytes.TrimSpace(rootPEM)) {
		t.Fatal("proto round trip lost certificate root or verify usage")
	}
	resolverWire, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	fields := xdnsTestResolverWireFields(t, resolverWire)
	if string(fields[1]) != "https+h3" || string(fields[2]) != wantURL || string(fields[3]) != "resolver.test" || string(fields[4]) != "127.0.0.1" {
		t.Fatal("resolver protobuf field numbers 1-4 changed")
	}
	var root xtls.Certificate
	if err := proto.Unmarshal(fields[5], &root); err != nil {
		t.Fatal(err)
	}
	if root.Usage != xtls.Certificate_AUTHORITY_VERIFY || !bytes.Equal(root.Certificate, bytes.TrimSpace(rootPEM)) {
		t.Fatal("certificate protobuf field 5 changed")
	}
	for _, usage := range []string{"encipherment", "issue", "unknown"} {
		t.Run(usage, func(t *testing.T) {
			var input XDNS
			if err := json.Unmarshal(document, &input); err != nil {
				t.Fatal(err)
			}
			input.Resolvers[0].Certificates[0].Usage = usage
			invalidJSON, err := json.Marshal(&input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildXDNSMaskJSON(string(invalidJSON)); err == nil {
				t.Fatal("resolver certificate accepted a non-verify usage")
			}
		})
	}
}
