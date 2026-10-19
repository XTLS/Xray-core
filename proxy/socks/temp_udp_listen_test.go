package socks

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func newTestUDPAssociation(t *testing.T) (*TempUDPConn, net.Conn) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		udp.Close()
		client.Close()
		server.Close()
	})
	return NewTempUDPConn(udp, client, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}), server
}

func assertUDPAssociationClosed(t *testing.T, association *TempUDPConn, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("TCP association was not closed: %v", err)
	}
	association.PacketConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := association.PacketConn.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP socket was not closed: %v", err)
	}
}

func TestUDPAssociationCloseBeforeTimeout(t *testing.T) {
	association, peer := newTestUDPAssociation(t)
	association.Close()
	assertUDPAssociationClosed(t, association, peer)
}

func TestUDPAssociationTimeoutClosesSockets(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
	}{
		{name: "immediate", timeout: 0},
		{name: "idle", timeout: time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			association, peer := newTestUDPAssociation(t)
			association.SetTimeout(test.timeout)
			assertUDPAssociationClosed(t, association, peer)
		})
	}
}

func TestUDPAssociationCloseWithActiveTimeout(t *testing.T) {
	association, peer := newTestUDPAssociation(t)
	association.SetTimeout(time.Minute)
	association.Close()
	assertUDPAssociationClosed(t, association, peer)
}

type failingUDPReplyConn struct {
	net.Conn
	writes int
	err    error
}

func (c *failingUDPReplyConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == 1 { // Authentication succeeds; the UDP ASSOCIATE reply fails.
		return len(b), nil
	}
	return 0, c.err
}

func (c *failingUDPReplyConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestUDPAssociationReplyFailure(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	replyError := errors.New("UDP ASSOCIATE reply failed")
	conn := &failingUDPReplyConn{Conn: client, err: replyError}
	session := &ServerSession{
		config:       &ServerConfig{UdpEnabled: true},
		localAddress: xnet.LocalHostIP,
		address:      xnet.LocalHostIP,
	}
	// SOCKS5, no authentication, UDP ASSOCIATE, unspecified client address/port.
	reader := bytes.NewReader([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	_, association, err := session.Handshake(reader, conn)
	if !errors.Is(err, replyError) || association != nil {
		t.Fatalf("handshake returned association %v, error %v; want reply error", association, err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("failed handshake did not close the TCP association: %v", err)
	}
}
