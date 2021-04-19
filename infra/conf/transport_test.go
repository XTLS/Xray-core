package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/global"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/headers/tls"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/quic"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/websocket"
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
		Mark: 0,
		Tfo:  -1,
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
		Mark: 0,
		Tfo:  65535,
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
		Mark: 0,
		Tfo:  -65535,
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
		Mark: 0,
		Tfo:  0,
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
		Mark: 0,
		Tfo:  0,
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
		Mark: 0,
		Tfo:  0,
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

func TestTransportConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(TransportConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"tcpSettings": {
					"header": {
						"type": "http",
						"request": {
							"version": "1.1",
							"method": "GET",
							"path": "/b",
							"headers": {
								"a": "b",
								"c": "d"
							}
						},
						"response": {
							"version": "1.0",
							"status": "404",
							"reason": "Not Found"
						}
					}
				},
				"kcpSettings": {
					"mtu": 1200,
					"header": {
						"type": "none"
					}
				},
				"wsSettings": {
					"path": "/t"
				},
				"quicSettings": {
					"key": "abcd",
					"header": {
						"type": "dtls"
					}
				},
				"grpcSettings": {
					"serviceName": "name",
					"multiMode": true
				}
			}`,
			Parser: createParser(),
			Output: &global.Config{
				TransportSettings: []*internet.TransportConfig{
					{
						ProtocolName: "tcp",
						Settings: serial.ToTypedMessage(&tcp.Config{
							HeaderSettings: serial.ToTypedMessage(&http.Config{
								Request: &http.RequestConfig{
									Version: &http.Version{Value: "1.1"},
									Method:  &http.Method{Value: "GET"},
									Uri:     []string{"/b"},
									Header: []*http.Header{
										{Name: "a", Value: []string{"b"}},
										{Name: "c", Value: []string{"d"}},
									},
								},
								Response: &http.ResponseConfig{
									Version: &http.Version{Value: "1.0"},
									Status:  &http.Status{Code: "404", Reason: "Not Found"},
									Header: []*http.Header{
										{
											Name:  "Content-Type",
											Value: []string{"application/octet-stream", "video/mpeg"},
										},
										{
											Name:  "Transfer-Encoding",
											Value: []string{"chunked"},
										},
										{
											Name:  "Connection",
											Value: []string{"keep-alive"},
										},
										{
											Name:  "Pragma",
											Value: []string{"no-cache"},
										},
										{
											Name:  "Cache-Control",
											Value: []string{"private", "no-cache"},
										},
									},
								},
							}),
						}),
					},
					{
						ProtocolName: "mkcp",
						Settings: serial.ToTypedMessage(&kcp.Config{
							Mtu:          &kcp.MTU{Value: 1200},
							HeaderConfig: serial.ToTypedMessage(&noop.Config{}),
						}),
					},
					{
						ProtocolName: "websocket",
						Settings: serial.ToTypedMessage(&websocket.Config{
							Path: "/t",
						}),
					},
					{
						ProtocolName: "quic",
						Settings: serial.ToTypedMessage(&quic.Config{
							Key: "abcd",
							Security: &protocol.SecurityConfig{
								Type: protocol.SecurityType_NONE,
							},
							Header: serial.ToTypedMessage(&tls.PacketConfig{}),
						}),
					},
					{
						ProtocolName: "grpc",
						Settings: serial.ToTypedMessage(&grpc.Config{
							ServiceName: "name",
							MultiMode:   true,
						}),
					},
				},
			},
		},
		{
			Input: `{
				"gunSettings": {
					"serviceName": "name"
				}
			}`,
			Parser: createParser(),
			Output: &global.Config{
				TransportSettings: []*internet.TransportConfig{
					{
						ProtocolName: "grpc",
						Settings: serial.ToTypedMessage(&grpc.Config{
							ServiceName: "name",
						}),
					},
				},
			},
		},
	})
}
