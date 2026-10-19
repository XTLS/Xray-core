package conf_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func TestSocksUDPSocketOptions(t *testing.T) {
	for _, protocol := range []string{"socks", "mixed"} {
		for _, test := range []struct {
			name, options string
			want          *SocketConfig
		}{
			{name: "absent"},
			{name: "null", options: `,"udpSockopt":null`},
			{name: "empty", options: `,"udpSockopt":{}`, want: &SocketConfig{}},
			{
				name:    "configured",
				options: `,"udpSockopt":{"mark":7,"v6only":true,"customSockopt":[{"system":"windows","network":"udp6","level":"65535","opt":"4098","value":"262144","type":"int"}]}`,
				want:    &SocketConfig{Mark: 7, V6only: true, CustomSockopt: []*CustomSockoptConfig{{System: "windows", Network: "udp6", Level: "65535", Opt: "4098", Value: "262144", Type: "int"}}},
			},
		} {
			t.Run(protocol+"/"+test.name, func(t *testing.T) {
				var inbound InboundDetourConfig
				input := fmt.Sprintf(`{
					"protocol":%q,"port":10808,"settings":{"udp":true},
					"streamSettings":{"sockopt":{"tcpFastOpen":true,"customSockopt":[
						{"level":"65535","opt":"4098","value":"131072","type":"int"}
					]}%s}
				}`, protocol, test.options)
				if err := json.Unmarshal([]byte(input), &inbound); err != nil {
					t.Fatal(err)
				}
				built, err := inbound.Build()
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := built.ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				stream := receiver.(*proxyman.ReceiverConfig).StreamSettings
				if stream.SocketSettings.ParseTFOValue() != 256 || stream.SocketSettings.CustomSockopt[0].Value != "131072" {
					t.Fatal("UDP settings changed the transport socket options")
				}
				memory, err := internet.ToMemoryStreamConfig(stream)
				if err != nil {
					t.Fatal(err)
				}
				if memory.UDPSocketSettings != stream.UdpSocketSettings {
					t.Fatal("UDP socket settings were lost during stream conversion")
				}
				if test.want == nil {
					if stream.UdpSocketSettings != nil {
						t.Fatal("legacy or null settings inherited transport socket options")
					}
					return
				}
				want, err := test.want.Build()
				if err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(stream.UdpSocketSettings, want) {
					t.Fatalf("UDP options = %v, want %v", stream.UdpSocketSettings, want)
				}
			})
		}
	}
}

func TestUDPSocketOptionsRejectUnsupportedHandlers(t *testing.T) {
	for _, input := range []string{
		`{"protocol":"http","port":10808,"streamSettings":{"udpSockopt":{}}}`,
		`{"protocol":"socks","port":10808,"settings":{"udp":false},"streamSettings":{"udpSockopt":{}}}`,
	} {
		var inbound InboundDetourConfig
		if err := json.Unmarshal([]byte(input), &inbound); err != nil {
			t.Fatal(err)
		}
		if _, err := inbound.Build(); err == nil || !strings.Contains(err.Error(), "udpSockopt") {
			t.Fatalf("error = %v, want unsupported UDP socket options", err)
		}
	}
	var outbound OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"freedom","streamSettings":{"udpSockopt":{}}}`), &outbound); err != nil {
		t.Fatal(err)
	}
	if _, err := outbound.Build(); err == nil || !strings.Contains(err.Error(), "udpSockopt") {
		t.Fatalf("error = %v, want unsupported UDP socket options", err)
	}
}

func TestUDPSocketConfigRejectsInvalidOptions(t *testing.T) {
	for _, test := range []struct{ name, input, message string }{
		{"TCP option", `{"tcpFastOpen":false}`, "tcpFastOpen"},
		{"dialer option", `{"interface":"Ethernet"}`, "interface"},
		{"unknown option", `{"customSockopts":[]}`, "customSockopts"},
		{"invalid tproxy", `{"tproxy":"typo"}`, "tproxy"},
		{"null option", `{"customSockopt":[null]}`, "must be an object"},
		{"TCP network", `{"customSockopt":[{"network":"tcp","level":"6","opt":"1","value":"1","type":"int"}]}`, "network"},
		{"invalid network", `{"customSockopt":[{"network":"ud","level":"1","opt":"8","value":"1","type":"int"}]}`, "network"},
		{"missing level", `{"customSockopt":[{"opt":"8","value":"1","type":"int"}]}`, "level"},
		{"invalid opt", `{"customSockopt":[{"level":"1","opt":"typo","value":"1","type":"int"}]}`, "opt"},
		{"invalid integer", `{"customSockopt":[{"level":"1","opt":"8","value":"typo","type":"int"}]}`, "integer value"},
		{"invalid type", `{"customSockopt":[{"level":"1","opt":"8","value":"1","type":"typo"}]}`, "type"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config StreamConfig
			err := json.Unmarshal([]byte(`{"udpSockopt":`+test.input+`}`), &config)
			if err == nil {
				_, err = config.Build()
			}
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestUDPSocketConfigSelectors(t *testing.T) {
	for _, network := range []string{"", "udp", "udp4", "udp6"} {
		for _, kind := range []string{"int", "str"} {
			t.Run(network+kind, func(t *testing.T) {
				option := &CustomSockoptConfig{System: "linux", Network: network, Level: "1", Opt: "8", Value: "1234", Type: kind}
				config := &UDPSocketConfig{TProxy: "tproxy", CustomSockopt: []*CustomSockoptConfig{option}}
				built, err := config.Build()
				if err != nil {
					t.Fatal(err)
				}
				if built.Tproxy != internet.SocketConfig_TProxy || built.CustomSockopt[0].Network != network || option.Network != network {
					t.Fatal("UDP socket option selectors were not preserved")
				}
			})
		}
	}
}
