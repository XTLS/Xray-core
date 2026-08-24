package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	finalmaskcustom "github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestSocketConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(SocketConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	// test "tcpFastOpen": true, queue length 256 is expected. other parameters are tested here too
	expectedOutput := &internet.SocketConfig{
		Mark:           1,
		Tfo:            256,
		DomainStrategy: internet.DomainStrategy_USE_IP,
		DialerProxy:    "tag",
		HappyEyeballs:  &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"mark": 1,
				"tcpFastOpen": true,
				"domainStrategy": "UseIP",
				"dialerProxy": "tag"
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 256 {
		t.Fatalf("unexpected parsed TFO value, which should be 256")
	}

	// test "tcpFastOpen": false, disabled TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -1,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": false
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 65535, queue length 65535 is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 65535 {
		t.Fatalf("unexpected parsed TFO value, which should be 65535")
	}

	// test "tcpFastOpen": -65535, disable TFO is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           -65535,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": -65535
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != 0 {
		t.Fatalf("unexpected parsed TFO value, which should be 0")
	}

	// test "tcpFastOpen": 0, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": 0
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test omit "tcpFastOpen", no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  `{}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}

	// test "tcpFastOpen": null, no operation is expected
	expectedOutput = &internet.SocketConfig{
		Mark:          0,
		Tfo:           0,
		HappyEyeballs: &internet.HappyEyeballsConfig{Interleave: 1, TryDelayMs: 0, PrioritizeIpv6: false, MaxConcurrentTry: 4},
	}
	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpFastOpen": null
			}`,
			Parser: createParser(),
			Output: expectedOutput,
		},
	})
	if expectedOutput.ParseTFOValue() != -1 {
		t.Fatalf("unexpected parsed TFO value, which should be -1")
	}
}

func TestHeaderCustomUDPBuild(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"client": [
					{
						"type": "hex",
						"packet": "aabb"
					},
					{
						"rand": 2,
						"capture": "seed",
						"randRange": "16-32"
					}
				],
				"server": [
					{
						"capture": "txid",
						"transform": {
							"op": "concat",
							"args": [
								{"reuse": "seed"},
								{"u64": 258},
								{"type": "hex", "bytes": "c0de"}
							]
						}
					},
					{
						"reuse": "txid"
					}
				],
				"mode": "standalone"
			}`,
			Parser: parser,
			Output: &finalmaskcustom.UDPStandaloneConfig{
				Client: []*finalmaskcustom.UDPItem{
					{
						RandMax: 255,
						Packet:  []byte{0xAA, 0xBB},
					},
					{
						Rand:    2,
						RandMin: 16,
						RandMax: 32,
						Save:    "seed",
					},
				},
				Server: []*finalmaskcustom.UDPItem{
					{
						RandMax: 255,
						Save:    "txid",
						Expr: &finalmaskcustom.Expr{
							Op: "concat",
							Args: []*finalmaskcustom.ExprArg{
								{
									Value: &finalmaskcustom.ExprArg_Var{
										Var: "seed",
									},
								},
								{
									Value: &finalmaskcustom.ExprArg_U64{
										U64: 258,
									},
								},
								{
									Value: &finalmaskcustom.ExprArg_Bytes{
										Bytes: []byte{0xC0, 0xDE},
									},
								},
							},
						},
					},
					{
						RandMax: 255,
						Var:     "txid",
					},
				},
			},
		},
	})
}

func TestHeaderCustomTCPBuildRejectsMixedItemKinds(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomTCP) })

	_, err := parser(`{
		"clients": [[
			{
				"packet": [1, 2],
				"reuse": "txid"
			}
		]]
	}`)
	if err == nil || !strings.Contains(err.Error(), "exactly one item kind") {
		t.Fatalf("expected mixed item kind rejection, got %v", err)
	}
}

func TestHeaderCustomUDPBuildRejectsInvalidVariableNames(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	_, err := parser(`{
		"client": [
			{
				"capture": "bad-name",
				"rand": 4
			}
		]
	}`)
	if err == nil || !strings.Contains(err.Error(), "invalid variable name") {
		t.Fatalf("expected invalid variable name rejection, got %v", err)
	}
}

func TestHeaderCustomUDPBuildRejectsExprWithoutArgs(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(HeaderCustomUDP) })

	_, err := parser(`{
		"client": [
			{
				"transform": {
					"op": "concat"
				}
			}
		]
	}`)
	if err == nil || !strings.Contains(err.Error(), "transform args") {
		t.Fatalf("expected transform arg rejection, got %v", err)
	}
}

func TestProxyProtocolTrustedSources(t *testing.T) {
	config := new(SocketConfig)
	if err := json.Unmarshal([]byte(`{
		"proxyProtocolMode": "trusted-sources",
		"proxyProtocolTrustedSources": ["192.0.2.10", "2001:db8::/32"],
		"proxyProtocolListenPorts": [18443]
	}`), config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.AcceptProxyProtocol {
		t.Fatal("source-aware mode unexpectedly enabled the legacy acceptProxyProtocol bit")
	}
	wire, err := proto.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	for len(wire) > 0 {
		fieldNumber, fieldType, tagLength := protowire.ConsumeTag(wire)
		if tagLength < 0 {
			t.Fatalf("invalid encoded SocketConfig: %v", protowire.ParseError(tagLength))
		}
		wire = wire[tagLength:]
		if fieldNumber == 7 {
			t.Fatal("source-aware config serialized the legacy accept_proxy_protocol field")
		}
		fieldLength := protowire.ConsumeFieldValue(fieldNumber, fieldType, wire)
		if fieldLength < 0 {
			t.Fatalf("invalid encoded SocketConfig field: %v", protowire.ParseError(fieldLength))
		}
		wire = wire[fieldLength:]
	}
	if len(built.ProxyProtocolTrustedSources) != 2 {
		t.Fatalf("unexpected trusted source count: %d", len(built.ProxyProtocolTrustedSources))
	}
	if built.ProxyProtocolMode != internet.SocketConfig_ProxyProtocolTrustedSources {
		t.Fatalf("unexpected proxy protocol mode: %v", built.ProxyProtocolMode)
	}
	if len(built.ProxyProtocolListenPorts) != 1 || built.ProxyProtocolListenPorts[0] != 18443 {
		t.Fatalf("unexpected proxy protocol listen ports: %v", built.ProxyProtocolListenPorts)
	}

	for _, input := range []string{
		`{"proxyProtocolTrustedSources":["192.0.2.10"]}`,
		`{"proxyProtocolMode":"trusted-sources"}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["not-an-address"]}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["192.0.2.10/24"]}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["fe80::1"]}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["fe80::/10"]}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["192.0.2.10"],"proxyProtocolListenPorts":[0]}`,
		`{"proxyProtocolMode":"trusted-sources","proxyProtocolTrustedSources":["192.0.2.10"],"proxyProtocolListenPorts":[18443,18443]}`,
		`{"proxyProtocolMode":"unknown","proxyProtocolTrustedSources":["192.0.2.10"]}`,
	} {
		config := new(SocketConfig)
		if err := json.Unmarshal([]byte(input), config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil {
			t.Fatalf("expected configuration error for %s", input)
		}
	}
}

func TestProxyProtocolTrustedSourcesRejectsLegacyTransportSettings(t *testing.T) {
	for _, test := range []struct {
		name    string
		network string
		field   string
	}{
		{name: "raw", network: "tcp", field: "rawSettings"},
		{name: "websocket", network: "ws", field: "wsSettings"},
		{name: "httpupgrade", network: "httpupgrade", field: "httpupgradeSettings"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `{
				"network":"` + test.network + `",
				"` + test.field + `":{"acceptProxyProtocol":true},
				"sockopt":{
					"proxyProtocolMode":"trusted-sources",
					"proxyProtocolTrustedSources":["192.0.2.10"]
				}
			}`
			config := new(StreamConfig)
			if err := json.Unmarshal([]byte(input), config); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Build(); err == nil {
				t.Fatal("source-aware mode accepted a legacy transport-level acceptProxyProtocol flag")
			}
		})
	}
}
