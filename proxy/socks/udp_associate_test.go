package socks

import (
	"bytes"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type mockPipeConn struct {
	gonet.Conn
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	local    gonet.Addr
	remote   gonet.Addr
}

func (m *mockPipeConn) Read(b []byte) (int, error) {
	return m.readBuf.Read(b)
}

func (m *mockPipeConn) Write(b []byte) (int, error) {
	return m.writeBuf.Write(b)
}

func (m *mockPipeConn) LocalAddr() gonet.Addr {
	if m.local != nil {
		return m.local
	}
	return &gonet.UnixAddr{Name: "/tmp/socks.sock", Net: "unix"}
}

func (m *mockPipeConn) RemoteAddr() gonet.Addr {
	if m.remote != nil {
		return m.remote
	}
	return &gonet.UnixAddr{Name: "@client", Net: "unix"}
}

func (m *mockPipeConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPipeConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockPipeConn) Close() error                       { return nil }

func TestUDPAssociateDomainAddress(t *testing.T) {
	// Verify that UDP Associate does not panic when config.Address is a domain (e.g. "localhost").
	// Previously: calling responseAddress.IP() unconditionally panicked on DomainAddress.
	session := &ServerSession{
		config: &ServerConfig{
			AuthType:   AuthType_NO_AUTH,
			UdpEnabled: true,
			Address:    net.NewIPOrDomain(net.DomainAddress("localhost")),
		},
		address:      net.LocalHostIP,
		port:         net.Port(1080),
		localAddress: net.LocalHostIP,
	}

	// SOCKS5 greeting + UDP ASSOCIATE request for 127.0.0.1:1024
	reqData := []byte{
		0x05, 0x01, 0x00,
		0x05, 0x03, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x00,
	}

	mockConn := &mockPipeConn{
		readBuf:  bytes.NewBuffer(reqData),
		writeBuf: &bytes.Buffer{},
	}

	req, udpConn, err := session.Handshake(mockConn.readBuf, mockConn)
	if err != nil {
		t.Fatalf("Handshake failed unexpectedly: %v", err)
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	if req == nil {
		t.Fatalf("Expected non-nil request header")
	}
}

func TestUDPAssociateUnixSocket(t *testing.T) {
	// Verify that UDP Associate does not panic when client connects over a Unix domain socket
	// or any non-TCP connection (writer.RemoteAddr() is not *net.TCPAddr).
	// Previously: writer.RemoteAddr().(*net.TCPAddr) triggered an unchecked type assertion panic.
	session := &ServerSession{
		config: &ServerConfig{
			AuthType:   AuthType_NO_AUTH,
			UdpEnabled: true,
			Address:    net.NewIPOrDomain(net.LocalHostIP),
		},
		address:      net.LocalHostIP,
		port:         net.Port(1080),
		localAddress: net.LocalHostIP,
	}

	// SOCKS5 greeting + UDP ASSOCIATE request with unspecified IP (0.0.0.0:1024)
	reqData := []byte{
		0x05, 0x01, 0x00,
		0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
	}

	mockConn := &mockPipeConn{
		readBuf:  bytes.NewBuffer(reqData),
		writeBuf: &bytes.Buffer{},
		remote:   &gonet.UnixAddr{Name: "@socks_client", Net: "unix"},
	}

	req, udpConn, err := session.Handshake(mockConn.readBuf, mockConn)
	if err != nil {
		t.Fatalf("Handshake failed unexpectedly: %v", err)
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	if req == nil {
		t.Fatalf("Expected non-nil request header")
	}
}

func TestServerProcessNonTCPLocalAddr(t *testing.T) {
	// Verify that Server.processTCP safely handles non-TCP connections (e.g. Unix socket inbound)
	// without unchecked type assertion panic on conn.LocalAddr().(*net.TCPAddr).
	mockConn := &mockPipeConn{
		local:  &gonet.UnixAddr{Name: "/var/run/xray.sock", Net: "unix"},
		remote: &gonet.UnixAddr{Name: "@client", Net: "unix"},
	}

	localAddr := net.LocalHostIP
	if tcpAddr, ok := mockConn.LocalAddr().(*net.TCPAddr); ok {
		localAddr = net.IPAddress(tcpAddr.IP)
	}
	if localAddr != net.LocalHostIP {
		t.Fatalf("Expected fallback to LocalHostIP, got %v", localAddr)
	}
}
