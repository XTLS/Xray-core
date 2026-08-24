package internet

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestValidateProxyProtocolConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *SocketConfig
		wantErr bool
	}{
		{name: "nil config"},
		{name: "disabled", config: &SocketConfig{}},
		{name: "legacy require all", config: &SocketConfig{AcceptProxyProtocol: true}},
		{
			name: "trusted exact addresses and canonical CIDR",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10", "2001:db8::/32"},
				ProxyProtocolListenPorts:    []uint32{18443},
			},
		},
		{
			name: "CIDR blocks remain supported",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"198.51.100.0/24", "0.0.0.0/0"},
			},
		},
		{
			name: "sources without explicit mode",
			config: &SocketConfig{
				AcceptProxyProtocol:         true,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
			},
			wantErr: true,
		},
		{
			name: "ports without explicit mode",
			config: &SocketConfig{
				ProxyProtocolListenPorts: []uint32{18443},
			},
			wantErr: true,
		},
		{
			name: "trusted mode requires sources",
			config: &SocketConfig{
				ProxyProtocolMode: SocketConfig_ProxyProtocolTrustedSources,
			},
			wantErr: true,
		},
		{
			name: "trusted mode rejects legacy accept flag",
			config: &SocketConfig{
				AcceptProxyProtocol:         true,
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
			},
			wantErr: true,
		},
		{
			name: "invalid source",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"not-an-address"},
			},
			wantErr: true,
		},
		{
			name: "non-canonical CIDR",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10/24"},
			},
			wantErr: true,
		},
		{
			name: "IPv4-mapped CIDR",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"::ffff:192.0.2.0/120"},
			},
			wantErr: true,
		},
		{
			name: "IPv6 link-local address",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"fe80::1"},
			},
			wantErr: true,
		},
		{
			name: "IPv6 link-local prefix",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"fe80::/10"},
			},
			wantErr: true,
		},
		{
			name: "IPv6 prefix overlapping link-local space",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"fe00::/8"},
			},
			wantErr: true,
		},
		{
			name: "invalid port zero",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
				ProxyProtocolListenPorts:    []uint32{0},
			},
			wantErr: true,
		},
		{
			name: "duplicate port",
			config: &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
				ProxyProtocolListenPorts:    []uint32{18443, 18443},
			},
			wantErr: true,
		},
		{
			name: "unknown programmatic mode",
			config: &SocketConfig{
				ProxyProtocolMode: SocketConfig_ProxyProtocolMode(99),
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateProxyProtocolConfig(test.config)
			if test.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateProxyProtocolTransportConfigRejectsLegacyFlag(t *testing.T) {
	config := &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
	}
	if err := ValidateProxyProtocolTransportConfig(config, legacyProxyProtocolTransport{accept: false}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxyProtocolTransportConfig(config, legacyProxyProtocolTransport{accept: true}); err == nil {
		t.Fatal("source-aware mode accepted a programmatic legacy transport flag")
	}
}

func TestValidateProxyProtocolListenerSet(t *testing.T) {
	ports := func(values ...uint32) *xnet.PortList {
		list := &xnet.PortList{}
		for _, value := range values {
			list.Range = append(list.Range, xnet.SinglePortRange(xnet.Port(value)))
		}
		return list
	}

	for _, test := range []struct {
		name          string
		listenerPorts *xnet.PortList
		proxyPorts    []uint32
		wantErr       bool
	}{
		{name: "same-port TCP", listenerPorts: ports(443)},
		{name: "dedicated port intersects", listenerPorts: ports(443, 18443), proxyPorts: []uint32{18443}},
		{name: "one of several dedicated ports is missing", listenerPorts: ports(443, 18443), proxyPorts: []uint32{18443, 28443}, wantErr: true},
		{name: "dedicated ports miss all listeners", listenerPorts: ports(443), proxyPorts: []uint32{18443}, wantErr: true},
		{name: "Unix listener", listenerPorts: nil, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
				ProxyProtocolListenPorts:    test.proxyPorts,
			}
			err := ValidateProxyProtocolListenerSet(config, test.listenerPorts)
			if test.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateProxyProtocolInboundConfigRejectsUDPBeforeWorkers(t *testing.T) {
	config := &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
	}
	ports := &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(443)}}
	stream := &MemoryStreamConfig{ProtocolName: "tcp"}
	if err := ValidateProxyProtocolInboundConfig(config, ports, []xnet.Network{xnet.Network_TCP}, stream); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxyProtocolInboundConfig(config, ports, []xnet.Network{xnet.Network_UDP}, stream); err == nil {
		t.Fatal("source-aware UDP inbound passed validation")
	}
	if err := ValidateProxyProtocolInboundConfig(config, ports, []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}, stream); err == nil {
		t.Fatal("source-aware mixed TCP/UDP inbound passed validation")
	}
}

func TestValidateProxyProtocolInboundConfigRejectsPacketTransports(t *testing.T) {
	config := &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
	}
	ports := &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(443)}}
	tests := []struct {
		name     string
		protocol string
		security interface{}
		wantErr  bool
	}{
		{name: "default TCP"},
		{name: "RAW TCP", protocol: "tcp"},
		{name: "WebSocket", protocol: "websocket"},
		{name: "HTTPUpgrade", protocol: "httpupgrade"},
		{name: "gRPC", protocol: "grpc"},
		{name: "XHTTP H2", protocol: "splithttp", security: nextProtocolSettings{next: []string{"h2"}}},
		{name: "mKCP", protocol: "mkcp", wantErr: true},
		{name: "Hysteria", protocol: "hysteria", wantErr: true},
		{name: "XHTTP H3", protocol: "splithttp", security: nextProtocolSettings{next: []string{"h3"}}, wantErr: true},
		{name: "unknown transport", protocol: "custom-packet", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateProxyProtocolInboundConfig(config, ports, []xnet.Network{xnet.Network_TCP}, &MemoryStreamConfig{
				ProtocolName:     test.protocol,
				SecuritySettings: test.security,
			})
			if test.wantErr && err == nil {
				t.Fatal("expected effective transport validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyProtocolTrustedSourcesRejectsPacketListener(t *testing.T) {
	packet, err := (&DefaultListener{}).ListenPacket(context.Background(), &net.UDPAddr{IP: net.IPv4zero, Port: 0}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"127.0.0.1"},
	})
	if packet != nil {
		_ = packet.Close()
		t.Fatal("unexpected packet listener")
	}
	if err == nil {
		t.Fatal("expected trusted-sources packet listener error")
	}
}

func TestCanUseXForwardedFor(t *testing.T) {
	if !CanUseXForwardedFor(nil, 443) || !CanUseXForwardedFor(&SocketConfig{}, 443) {
		t.Fatal("legacy HTTP transport behavior changed")
	}
	if CanUseXForwardedFor(&SocketConfig{ProxyProtocolMode: SocketConfig_ProxyProtocolTrustedSources}, 443) {
		t.Fatal("X-Forwarded-For can override a same-port source-aware PROXY address")
	}
	dedicated := &SocketConfig{
		ProxyProtocolMode:        SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolListenPorts: []uint32{18443},
	}
	if !CanUseXForwardedFor(dedicated, 443) {
		t.Fatal("dedicated direct listener lost legacy X-Forwarded-For behavior")
	}
	if CanUseXForwardedFor(dedicated, 18443) {
		t.Fatal("X-Forwarded-For can override a dedicated source-aware PROXY address")
	}
}

func TestProxyProtocolListenerPolicy(t *testing.T) {
	samePortConfig := &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10", "2001:db8::/32"},
	}
	listenerConfig, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 443}, samePortConfig)
	if err != nil {
		t.Fatal(err)
	}
	if listenerConfig == nil {
		t.Fatal("source-aware listener config is missing")
	}

	for _, test := range []struct {
		address string
		want    proxyproto.Policy
	}{
		{address: "192.0.2.10", want: proxyproto.REQUIRE},
		{address: "::ffff:192.0.2.10", want: proxyproto.REQUIRE},
		{address: "192.0.2.11", want: proxyproto.SKIP},
		{address: "2001:db8::10", want: proxyproto.REQUIRE},
		{address: "2001:db9::10", want: proxyproto.SKIP},
	} {
		got, err := listenerConfig.policy(proxyproto.ConnPolicyOptions{
			Upstream: &net.TCPAddr{IP: net.ParseIP(test.address), Port: 1234},
		})
		if err != nil {
			t.Fatalf("policy(%s): %v", test.address, err)
		}
		if got != test.want {
			t.Fatalf("policy(%s) = %v, want %v", test.address, got, test.want)
		}
	}
	if policy, err := listenerConfig.policy(proxyproto.ConnPolicyOptions{
		Upstream: &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 1234, Zone: "en0"},
	}); err != nil || policy != proxyproto.SKIP {
		t.Fatalf("scoped IPv6 peer policy = %v, %v; want SKIP", policy, err)
	}

	dedicatedConfig := &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
		ProxyProtocolListenPorts:    []uint32{18443},
	}
	directListener, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 443}, dedicatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if directListener != nil {
		t.Fatal("direct port unexpectedly enabled PROXY protocol")
	}

	gatewayListener, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 18443}, dedicatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if gatewayListener == nil {
		t.Fatal("gateway port did not enable PROXY protocol")
	}
	if _, err := gatewayListener.policy(proxyproto.ConnPolicyOptions{
		Upstream: &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234},
	}); !stderrors.Is(err, proxyproto.ErrInvalidUpstream) {
		t.Fatalf("untrusted gateway-port peer error = %v, want ErrInvalidUpstream", err)
	}
	if _, err := gatewayListener.policy(proxyproto.ConnPolicyOptions{
		Upstream: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234, Zone: "en0"},
	}); !stderrors.Is(err, proxyproto.ErrInvalidUpstream) {
		t.Fatalf("scoped gateway-port peer error = %v, want ErrInvalidUpstream", err)
	}
	if _, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, dedicatedConfig); err == nil {
		t.Fatal("dedicated source-aware selection accepted TCP port 0")
	}
}

func TestValidateSourceAwareProxyHeader(t *testing.T) {
	validV4 := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	)
	validV6 := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443},
	)
	validV4WithTLV := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	)
	if err := validV4WithTLV.SetTLVs([]proxyproto.TLV{{
		Type:  proxyproto.PP2_TYPE_ALPN,
		Value: []byte("h2"),
	}}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		header  *proxyproto.Header
		wantErr bool
	}{
		{name: "valid TCPv4", header: validV4},
		{name: "valid TCPv6", header: validV6},
		{name: "valid TCPv4 with TLV", header: validV4WithTLV},
		{name: "missing", wantErr: true},
		{
			name: "version one is unsupported",
			header: proxyproto.HeaderProxyFromAddrs(1,
				&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "LOCAL command",
			header: &proxyproto.Header{
				Version:           2,
				Command:           proxyproto.LOCAL,
				TransportProtocol: proxyproto.UNSPEC,
			},
			wantErr: true,
		},
		{
			name: "UDP transport",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
				&net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "zero source port",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 0},
				&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "unspecified source IP",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.IPv4zero, Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "multicast source IPv4",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("224.0.0.1"), Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "multicast source IPv6",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("ff02::1"), Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "limited broadcast source IPv4",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.IPv4bcast, Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "unspecified destination IPv4",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
				&net.TCPAddr{IP: net.IPv4zero, Port: 443},
			),
			wantErr: true,
		},
		{
			name: "unspecified destination IPv6",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 12345},
				&net.TCPAddr{IP: net.IPv6unspecified, Port: 443},
			),
			wantErr: true,
		},
		{
			name: "multicast destination IPv4",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("224.0.0.1"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "multicast destination IPv6",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 12345},
				&net.TCPAddr{IP: net.ParseIP("ff02::1"), Port: 443},
			),
			wantErr: true,
		},
		{
			name: "limited broadcast destination IPv4",
			header: proxyproto.HeaderProxyFromAddrs(2,
				&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
				&net.TCPAddr{IP: net.IPv4bcast, Port: 443},
			),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSourceAwareProxyHeader(test.header)
			if test.wantErr && err == nil {
				t.Fatal("expected header validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyProtocolSourceAwareDataPlane(t *testing.T) {
	const payload = "VLESS-client-hello"
	validHeader := formatProxyHeader(t, proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	))
	malformedTLVHeader := append([]byte{}, validHeader...)
	malformedTLVHeader[15]++ // Extend the PPv2 payload by one truncated TLV byte.
	malformedTLVHeader = append(malformedTLVHeader, byte(proxyproto.PP2_TYPE_ALPN))
	v1Header := []byte("PROXY TCP4 203.0.113.7 192.0.2.20 12345 443\r\n")
	v1HeaderWithExtraField := []byte("PROXY TCP4 203.0.113.7 192.0.2.20 12345 443 ignored\r\n")
	unknownHeader := []byte("PROXY UNKNOWN\r\n")
	localHeader := formatProxyHeader(t, &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.LOCAL,
		TransportProtocol: proxyproto.UNSPEC,
	})

	tests := []struct {
		name         string
		peerIP       string
		wire         []byte
		wantPayload  []byte
		wantError    bool
		wantRawConn  bool
		wantRemoteIP string
	}{
		{
			name:         "trusted gateway with strict PPv2 header",
			peerIP:       "192.0.2.10",
			wire:         append(append([]byte{}, validHeader...), payload...),
			wantPayload:  []byte(payload),
			wantRemoteIP: "203.0.113.7",
		},
		{
			name:      "trusted gateway without header",
			peerIP:    "192.0.2.10",
			wire:      []byte(payload),
			wantError: true,
		},
		{
			name:      "trusted gateway with v1 header",
			peerIP:    "192.0.2.10",
			wire:      append(append([]byte{}, v1Header...), payload...),
			wantError: true,
		},
		{
			name:      "trusted gateway with v1 extra field",
			peerIP:    "192.0.2.10",
			wire:      append(append([]byte{}, v1HeaderWithExtraField...), payload...),
			wantError: true,
		},
		{
			name:      "trusted gateway with UNKNOWN header",
			peerIP:    "192.0.2.10",
			wire:      append(append([]byte{}, unknownHeader...), payload...),
			wantError: true,
		},
		{
			name:      "trusted gateway with LOCAL header",
			peerIP:    "192.0.2.10",
			wire:      append(append([]byte{}, localHeader...), payload...),
			wantError: true,
		},
		{
			name:      "trusted gateway with truncated PPv2 TLV",
			peerIP:    "192.0.2.10",
			wire:      append(append([]byte{}, malformedTLVHeader...), payload...),
			wantError: true,
		},
		{
			name:        "direct client without header",
			peerIP:      "192.0.2.11",
			wire:        []byte(payload),
			wantPayload: []byte(payload),
			wantRawConn: true,
		},
		{
			name:        "direct client PROXY bytes remain unparsed",
			peerIP:      "192.0.2.11",
			wire:        append(append([]byte{}, validHeader...), payload...),
			wantPayload: append(append([]byte{}, validHeader...), payload...),
			wantRawConn: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listenerConfig, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 443}, &SocketConfig{
				ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
				ProxyProtocolTrustedSources: []string{"192.0.2.10"},
			})
			if err != nil {
				t.Fatal(err)
			}

			rawServer, client := net.Pipe()
			server := &addressedConn{
				Conn:   rawServer,
				remote: &net.TCPAddr{IP: net.ParseIP(test.peerIP), Port: 1234},
				local:  &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
			}
			t.Cleanup(func() {
				_ = server.Close()
				_ = client.Close()
			})

			writeDone := make(chan error, 1)
			go func() {
				_, err := client.Write(test.wire)
				writeDone <- err
			}()

			listener := &proxyproto.Listener{
				Listener:          &singleConnListener{conn: server},
				ConnPolicy:        listenerConfig.policy,
				ValidateHeader:    listenerConfig.validator,
				ReadHeaderTimeout: time.Second,
			}
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			if test.wantRawConn && conn != server {
				t.Fatalf("SKIP returned wrapped connection %T", conn)
			}
			readSize := len(test.wantPayload)
			if readSize == 0 {
				readSize = len(payload)
			}
			buf := make([]byte, readSize)
			n, err := io.ReadFull(conn, buf)
			if test.wantError {
				if err == nil {
					t.Fatalf("expected connection rejection, got %q", buf[:n])
				}
				_ = conn.Close()
				<-writeDone
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := string(buf[:n]); got != string(test.wantPayload) {
				t.Fatalf("payload = %q, want %q", got, test.wantPayload)
			}
			if test.wantRemoteIP != "" && !strings.HasPrefix(conn.RemoteAddr().String(), test.wantRemoteIP+":") {
				t.Fatalf("remote address = %q, want IP %s", conn.RemoteAddr(), test.wantRemoteIP)
			}
			_ = conn.Close()
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyProtocolSourceAwareRejectsFragmentedV1(t *testing.T) {
	listenerConfig, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 443}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}

	rawServer, client := net.Pipe()
	server := &addressedConn{
		Conn:   rawServer,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234},
		local:  &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	writeDone := make(chan error, 1)
	go func() {
		if _, err := client.Write([]byte("PROXY TCP4 203.0.113.7")); err != nil {
			writeDone <- err
			return
		}
		_, err := client.Write([]byte(" 192.0.2.20 12345 443\r\n"))
		writeDone <- err
	}()

	listener := &proxyproto.Listener{
		Listener:          &singleConnListener{conn: server},
		ConnPolicy:        listenerConfig.policy,
		ValidateHeader:    listenerConfig.validator,
		ReadHeaderTimeout: time.Second,
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); err == nil {
		t.Fatal("fragmented PROXY v1 header was accepted")
	}
	_ = conn.Close()
	<-writeDone
}

func TestProxyProtocolSourceAwareTCPListener(t *testing.T) {
	listener, err := (&DefaultListener{}).Listen(context.Background(), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	const payload = "listener-payload"
	header := formatProxyHeader(t, proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	))
	if _, err := client.Write(append(header, payload...)); err != nil {
		t.Fatal(err)
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("payload = %q, want %q", buf, payload)
	}
	if !strings.HasPrefix(conn.RemoteAddr().String(), "203.0.113.7:") {
		t.Fatalf("remote address = %q, want claimed client IP", conn.RemoteAddr())
	}
}

func TestProxyProtocolDedicatedPortDropsUntrustedBeforeRead(t *testing.T) {
	listenerConfig, err := newProxyProtocolListenerConfig(&net.TCPAddr{IP: net.IPv4zero, Port: 18443}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"192.0.2.10"},
		ProxyProtocolListenPorts:    []uint32{18443},
	})
	if err != nil {
		t.Fatal(err)
	}

	rawServer, client := net.Pipe()
	server := &addressedConn{
		Conn:   rawServer,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234},
		local:  &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 18443},
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	listener := &proxyproto.Listener{
		Listener:   &singleConnListener{conn: server},
		ConnPolicy: listenerConfig.policy,
	}
	if _, err := listener.Accept(); !stderrors.Is(err, io.EOF) {
		t.Fatalf("Accept error = %v, want EOF after dropping the only untrusted connection", err)
	}
	if _, err := client.Write([]byte("PROXY-looking bytes")); err == nil {
		t.Fatal("untrusted connection remained writable after policy drop")
	}
}

func TestProxyProtocolDedicatedModeLeavesDirectListenerUnwrapped(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directPort := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	proxyPort := uint32(18443)
	if uint32(directPort) == proxyPort {
		proxyPort++
	}
	listener, err := (&DefaultListener{}).Listen(context.Background(), &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: directPort}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"127.0.0.1"},
		ProxyProtocolListenPorts:    []uint32{proxyPort},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, wrapped := listener.(*proxyproto.Listener); wrapped {
		t.Fatal("direct listener was unexpectedly wrapped with PROXY protocol")
	}
}

func TestProxyProtocolTrustedSourcesRejectsUDSBeforeCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.sock")
	listener, err := (&DefaultListener{}).Listen(context.Background(), &net.UnixAddr{Name: path, Net: "unix"}, &SocketConfig{
		ProxyProtocolMode:           SocketConfig_ProxyProtocolTrustedSources,
		ProxyProtocolTrustedSources: []string{"127.0.0.1"},
	})
	if listener != nil {
		_ = listener.Close()
		t.Fatal("unexpected UDS listener")
	}
	if err == nil {
		t.Fatal("expected source-aware UDS configuration error")
	}
	for _, candidate := range []string{path, path + ".lock"} {
		if _, statErr := os.Stat(candidate); !os.IsNotExist(statErr) {
			t.Fatalf("source-aware UDS validation left %s behind: %v", candidate, statErr)
		}
	}
}

func TestProxyProtocolLegacyFilesystemUDS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets are unavailable")
	}
	tempDir, err := os.MkdirTemp("/tmp", "xray-uds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	path := filepath.Join(tempDir, "xray.sock")
	listener, err := (&DefaultListener{}).Listen(context.Background(), &net.UnixAddr{Name: path, Net: "unix"}, &SocketConfig{
		AcceptProxyProtocol: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	const payload = "uds-payload"
	header := formatProxyHeader(t, proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443},
	))
	if _, err := client.Write(append(header, payload...)); err != nil {
		t.Fatal(err)
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != payload {
		t.Fatalf("payload = %q, want %q", buf, payload)
	}
	if !strings.HasPrefix(conn.RemoteAddr().String(), "203.0.113.7:") {
		t.Fatalf("remote address = %q, want claimed client IP", conn.RemoteAddr())
	}
}

func formatProxyHeader(t *testing.T, header *proxyproto.Header) []byte {
	t.Helper()
	formatted, err := header.Format()
	if err != nil {
		t.Fatal(err)
	}
	return formatted
}

type addressedConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (conn *addressedConn) RemoteAddr() net.Addr { return conn.remote }
func (conn *addressedConn) LocalAddr() net.Addr  { return conn.local }

type singleConnListener struct {
	conn net.Conn
}

type legacyProxyProtocolTransport struct {
	accept bool
}

type nextProtocolSettings struct {
	next []string
}

func (settings nextProtocolSettings) GetNextProtocol() []string {
	return settings.next
}

func (transport legacyProxyProtocolTransport) GetAcceptProxyProtocol() bool {
	return transport.accept
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (*singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}
