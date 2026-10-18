package socks

import (
	"bytes"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type udpTestTCP struct {
	bytes.Buffer
	remote *net.TCPAddr
}

func (c *udpTestTCP) Close() error                     { return nil }
func (c *udpTestTCP) LocalAddr() net.Addr              { return c.remote }
func (c *udpTestTCP) RemoteAddr() net.Addr             { return c.remote }
func (c *udpTestTCP) SetDeadline(time.Time) error      { return nil }
func (c *udpTestTCP) SetReadDeadline(time.Time) error  { return nil }
func (c *udpTestTCP) SetWriteDeadline(time.Time) error { return nil }

func TestUDPAssociationAppliesWindowsBuffers(t *testing.T) {
	const receiveBuffer, sendBuffer = 262144, 131072
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			settings := &internet.SocketConfig{CustomSockopt: []*internet.CustomSockopt{
				{System: "windows", Network: "udp", Level: strconv.Itoa(syscall.SOL_SOCKET), Opt: strconv.Itoa(syscall.SO_RCVBUF), Value: strconv.Itoa(receiveBuffer), Type: "int"},
				{System: "windows", Network: "udp", Level: strconv.Itoa(syscall.SOL_SOCKET), Opt: strconv.Itoa(syscall.SO_SNDBUF), Value: strconv.Itoa(sendBuffer), Type: "int"},
			}}
			session := &ServerSession{
				config:         &ServerConfig{UdpEnabled: true},
				localAddress:   xnet.ParseAddress(ip),
				address:        xnet.ParseAddress(ip),
				socketSettings: settings,
			}
			tcp := &udpTestTCP{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 45678}}
			// No-auth method, UDP ASSOCIATE, unspecified IPv4 client address/port.
			reader := bytes.NewReader([]byte{0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
			_, connection, err := session.handshake5(1, reader, tcp)
			if err != nil {
				t.Fatal(err)
			}
			connection.SetTimeout(time.Minute)
			defer connection.Close()
			udp, ok := connection.PacketConn.(*net.UDPConn)
			if !ok {
				t.Fatal("unexpected packet socket")
			}
			raw, err := udp.SyscallConn()
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
			if receive != receiveBuffer || send != sendBuffer {
				t.Fatalf("UDP buffers = %d/%d; configured buffers were ignored", receive, send)
			}
		})
	}
}
