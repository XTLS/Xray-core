package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	finalmaskcustom "github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/splithttp"
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
			Output: &finalmaskcustom.UDPConfig{
				Mode: "standalone",
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

func TestSplitHTTPCompressionBuild(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(SplitHTTPConfig) })

	msg, err := parser(`{
		"mode": "packet-up",
		"uplinkDataPlacement": "body",
		"compression": {
			"type": "zstd",
			"bufferSize": 262144,
			"compressLevel": 3
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	config := msg.(*splithttp.Config)
	if config.Compression == nil {
		t.Fatal("expected compression config")
	}
	if config.Compression.Type != "zstd" {
		t.Fatalf("unexpected compression type: %q", config.Compression.Type)
	}
	if config.Compression.BufferSize != 262144 {
		t.Fatalf("unexpected buffer size: %d", config.Compression.BufferSize)
	}
	if config.Compression.CompressLevel != 3 {
		t.Fatalf("unexpected compress level: %d", config.Compression.CompressLevel)
	}
}

func TestSplitHTTPCompressionBuildRejectsUnsupportedType(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(SplitHTTPConfig) })

	_, err := parser(`{
		"compression": {
			"type": "br"
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "unsupported compression type") {
		t.Fatalf("expected unsupported compression type rejection, got %v", err)
	}
}

func TestSplitHTTPCompressionBuildRejectsSmallBuffer(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(SplitHTTPConfig) })

	_, err := parser(`{
		"compression": {
			"type": "zstd",
			"bufferSize": 1
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "compression bufferSize") {
		t.Fatalf("expected compression buffer size rejection, got %v", err)
	}
}

func TestSplitHTTPCompressionBuildRejectsHeaderAndCookiePayload(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(SplitHTTPConfig) })

	for _, placement := range []string{"header", "cookie"} {
		_, err := parser(`{
			"mode": "packet-up",
			"uplinkDataPlacement": "` + placement + `",
			"compression": {
				"type": "zstd"
			}
		}`)
		if err == nil || !strings.Contains(err.Error(), "compression cannot be used with uplinkDataPlacement") {
			t.Fatalf("expected %s payload placement rejection, got %v", placement, err)
		}
	}
}

func TestSplitHTTPCompressionBuildRejectsInvalidLz4Level(t *testing.T) {
	parser := loadJSON(func() Buildable { return new(SplitHTTPConfig) })

	_, err := parser(`{
		"compression": {
			"type": "lz4",
			"compressLevel": 10
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "unsupported lz4 compressLevel") {
		t.Fatalf("expected lz4 compressLevel rejection, got %v", err)
	}
}
