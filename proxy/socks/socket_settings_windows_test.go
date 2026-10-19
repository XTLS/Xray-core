package socks

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func socketBuffers(t *testing.T, conn syscall.Conn) (int, int) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var receive, send int
	var socketError error
	err = raw.Control(func(fd uintptr) {
		receive, socketError = syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if socketError == nil {
			send, socketError = syscall.GetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		}
	})
	if err != nil || socketError != nil {
		t.Fatalf("get socket buffers: %v / %v", err, socketError)
	}
	return receive, send
}

func bufferOptions(network string, receive, send int) *internet.SocketConfig {
	return &internet.SocketConfig{CustomSockopt: []*internet.CustomSockopt{
		{System: "windows", Network: network, Level: strconv.Itoa(syscall.SOL_SOCKET), Opt: strconv.Itoa(syscall.SO_RCVBUF), Value: strconv.Itoa(receive), Type: "int"},
		{System: "windows", Network: network, Level: strconv.Itoa(syscall.SOL_SOCKET), Opt: strconv.Itoa(syscall.SO_SNDBUF), Value: strconv.Itoa(send), Type: "int"},
	}}
}

func TestUDPAssociationIndependentSocketOptions(t *testing.T) {
	const tcpReceive, tcpSend = 131072, 98304
	const udpReceive, udpSend = 262144, 196608
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for _, mode := range []string{"legacy", "empty", "explicit"} {
			t.Run(ip+"/"+mode, func(t *testing.T) {
				// Measure OS defaults rather than assuming a fixed Windows buffer size.
				baseline, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
				if err != nil {
					t.Fatal(err)
				}
				defer baseline.Close()
				wantReceive, wantSend := socketBuffers(t, baseline)
				var options *internet.SocketConfig
				switch mode {
				case "empty":
					options = &internet.SocketConfig{}
				case "explicit":
					options = bufferOptions("udp", udpReceive, udpSend)
					wantReceive, wantSend = udpReceive, udpSend
				}

				// Unscoped legacy custom options must not start affecting UDP.
				listener, err := internet.ListenSystem(context.Background(), &net.TCPAddr{IP: net.ParseIP(ip)}, bufferOptions("", tcpReceive, tcpSend))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
				client, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				accepted, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer accepted.Close()
				accepted.SetDeadline(time.Now().Add(5 * time.Second))
				tcp := accepted.(*net.TCPConn)
				beforeReceive, beforeSend := socketBuffers(t, tcp)
				if beforeReceive != tcpReceive || beforeSend != tcpSend {
					t.Fatalf("TCP buffers = %d/%d, want %d/%d", beforeReceive, beforeSend, tcpReceive, tcpSend)
				}
				session := &ServerSession{
					config:            &ServerConfig{UdpEnabled: true},
					udpSocketSettings: options,
					localAddress:      xnet.ParseAddress(ip),
					address:           xnet.ParseAddress(ip),
				}
				// No-auth method, UDP ASSOCIATE, unspecified client address/port.
				reader := bytes.NewReader([]byte{0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
				_, connection, err := session.handshake5(1, reader, tcp)
				if err != nil {
					t.Fatal(err)
				}
				connection.SetTimeout(time.Minute)
				defer connection.Close()
				receive, send := socketBuffers(t, connection.PacketConn.(*net.UDPConn))
				if receive != wantReceive || send != wantSend {
					t.Fatalf("UDP buffers = %d/%d, want %d/%d", receive, send, wantReceive, wantSend)
				}
				afterReceive, afterSend := socketBuffers(t, tcp)
				if afterReceive != beforeReceive || afterSend != beforeSend {
					t.Fatal("UDP association changed TCP buffer settings")
				}
			})
		}
	}
}
