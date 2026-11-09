package scenarios

import (
	"bytes"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestVlessMuxCarrierReuse(t *testing.T) {
	testVlessMuxCarrierReuse(t, false)
}

func TestVlessMuxCarrierReuseVision(t *testing.T) {
	testVlessMuxCarrierReuse(t, true)
}

func testVlessMuxCarrierReuse(t *testing.T, vision bool) {
	const timeout = 5 * time.Second

	// Distinct responses detect delivery to the wrong UDP target.
	udpTarget := func(tag byte) net.Destination {
		t.Helper()
		sock, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sock.Close() })
		go func() {
			var data [2048]byte
			for {
				n, from, err := sock.ReadFromUDP(data[:])
				if err != nil {
					return
				}
				if n != 0 {
					data[0] ^= tag
				}
				if _, err := sock.WriteToUDP(data[:n], from); err != nil {
					return
				}
			}
		}()
		addr := sock.LocalAddr().(*stdnet.UDPAddr)
		return net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))
	}
	udpTargetA, udpTargetB := udpTarget(0x36), udpTarget(0x69)

	userID := uuid.New()
	vlessAccount := &vless.Account{Id: userID.String()}
	var serverStream, clientStream *internet.StreamConfig
	if vision {
		vlessAccount.Flow = vless.XRV
		ct, hash := cert.MustGenerate(nil, cert.CommonName("localhost"))
		tlsStream := func(settings *tls.Config) *internet.StreamConfig {
			settings.MinVersion = "1.3"
			settings.MaxVersion = "1.3"
			return &internet.StreamConfig{
				ProtocolName:     "tcp",
				SecurityType:     serial.GetMessageType(settings),
				SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(settings)},
			}
		}
		serverStream = tlsStream(&tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(ct)}})
		clientStream = tlsStream(&tls.Config{PinnedPeerCertSha256: [][]byte{hash[:]}})
	}
	account := serial.ToTypedMessage(vlessAccount)
	receive := func(port net.Port, stream *internet.StreamConfig) *serial.TypedMessage {
		return serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:         net.NewIPOrDomain(net.LocalHostIP),
			PortList:       &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			StreamSettings: stream,
		})
	}
	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: receive(serverPort, serverStream),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{
				Users: []*protocol.User{{Account: account}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	}

	// A TCP relay observes the physical connections and lets the test drop one
	// carrier without closing either Xray instance or the other carrier.
	relay, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	accepted := make(chan *stdnet.TCPConn, 16)
	stopRelay := make(chan struct{})
	t.Cleanup(func() { close(stopRelay) })
	go func() {
		for {
			carrier, err := relay.AcceptTCP()
			if err != nil {
				return
			}
			select {
			case accepted <- carrier:
			case <-stopRelay:
				carrier.Close()
				return
			}
			go func() {
				defer carrier.Close()
				server, err := stdnet.DialTimeout("tcp4", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), timeout)
				if err != nil {
					return
				}
				defer server.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(server, carrier)
					server.Close()
					close(done)
				}()
				io.Copy(carrier, server)
				carrier.Close()
				server.Close()
				<-done
			}()
		}
	}()

	udpPortA, udpPortB := udp.PickPort(), udp.PickPort()
	dokodemoInbound := func(port net.Port, target net.Destination) *core.InboundHandlerConfig {
		return &core.InboundHandlerConfig{
			ReceiverSettings: receive(port, nil),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				RewriteAddress:  net.NewIPOrDomain(target.Address),
				RewritePort:     uint32(target.Port),
				AllowedNetworks: []net.Network{target.Network},
			}),
		}
	}
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			dokodemoInbound(udpPortA, udpTargetA),
			dokodemoInbound(udpPortB, udpTargetB),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: clientStream,
				MultiplexSettings: &proxyman.MultiplexingConfig{
					Enabled:         true,
					Concurrency:     4,
					XudpConcurrency: 4,
				},
			}),
			ProxySettings: serial.ToTypedMessage(&outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: net.NewIPOrDomain(net.LocalHostIP),
					Port:    uint32(relay.Addr().(*stdnet.TCPAddr).Port),
					User:    &protocol.User{Account: account},
				},
			}),
		}},
	}
	// Vision only permits UDP children on a multiplexed connection.
	var tcpPort net.Port
	if !vision {
		target := &tcp.Server{MsgProcessor: xor}
		tcpTarget, err := target.Start()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { target.Close() })
		tcpPort = tcp.PickPort()
		clientConfig.Inbound = append(clientConfig.Inbound, dokodemoInbound(tcpPort, tcpTarget))
	}
	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CloseAllServers(servers) })

	dial := func(network string, port net.Port) stdnet.Conn {
		t.Helper()
		conn, err := stdnet.DialTimeout(network, stdnet.JoinHostPort("127.0.0.1", port.String()), timeout)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	write := func(conn stdnet.Conn, payload []byte) {
		t.Helper()
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("wrote %d of %d bytes: %v", n, len(payload), err)
		}
	}
	checkTCP := func(conn stdnet.Conn, payload string) {
		t.Helper()
		write(conn, []byte(payload))
		got, err := readFrom2(conn, timeout, len(payload))
		if err != nil || !bytes.Equal(got, xor([]byte(payload))) {
			t.Fatalf("TCP response to %q: %x, %v", payload, got, err)
		}
	}
	checkUDP := func(conn stdnet.Conn, payload []byte, tag byte) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		var got [2048]byte
		n, err := conn.Read(got[:])
		want := bytes.Clone(payload)
		want[0] ^= tag
		if err != nil || !bytes.Equal(got[:n], want) {
			t.Fatalf("UDP response with tag %x: got %d bytes, want %d, error %v", tag, n, len(want), err)
		}
	}
	takeCarrier := func() *stdnet.TCPConn {
		t.Helper()
		select {
		case carrier := <-accepted:
			return carrier
		case <-time.After(timeout):
			t.Fatal("no physical VLESS carrier was accepted")
			return nil
		}
	}
	assertNoExtraCarrier := func() {
		t.Helper()
		select {
		case <-accepted:
			t.Fatal("a logical session unexpectedly opened another physical carrier")
		default:
		}
	}

	var tcpCarrier *stdnet.TCPConn
	var second stdnet.Conn
	if !vision {
		first := dial("tcp4", tcpPort)
		checkTCP(first, "first")
		tcpCarrier = takeCarrier()
		second = dial("tcp4", tcpPort)
		checkTCP(second, "second")
		checkTCP(first, "first still live")
		assertNoExtraCarrier()
		first.Close()
		checkTCP(second, "second after first closed")
		assertNoExtraCarrier()
	}

	packetA, packetB := dial("udp4", udpPortA), dial("udp4", udpPortB)
	small := []byte{0x8d}
	large := bytes.Repeat([]byte{0xbe}, 1200)
	write(packetA, small)
	checkUDP(packetA, small, 0x36)
	takeCarrier()
	write(packetB, large)
	checkUDP(packetB, large, 0x69)
	write(packetA, large)
	write(packetB, small)
	checkUDP(packetA, large, 0x36)
	checkUDP(packetB, small, 0x69)
	assertNoExtraCarrier()

	if vision {
		return
	}

	tcpCarrier.Close()
	if err := second.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	n, err := second.Read(data[:])
	if ne, ok := err.(stdnet.Error); n != 0 || err == nil || (ok && ne.Timeout()) {
		t.Fatalf("TCP session survived carrier loss: read %d bytes, error %v", n, err)
	}
	write(packetA, small)
	checkUDP(packetA, small, 0x36)
	fresh := dial("tcp4", tcpPort)
	checkTCP(fresh, "fresh session after carrier loss")
	takeCarrier()
	assertNoExtraCarrier()
}
