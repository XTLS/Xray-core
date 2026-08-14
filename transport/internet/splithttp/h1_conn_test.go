package splithttp

import (
	"io"
	"net"
	"testing"
	"time"
)

// newPipeH1Conn creates an H1Conn over a real TCP pair and returns it
// together with the server side of the connection.
func newPipeH1Conn(t *testing.T) (*H1Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	return NewH1Conn(clientConn), serverConn
}

func TestH1ConnIdleTimeoutClosesConn(t *testing.T) {
	h1, server := newPipeH1Conn(t)

	h1.idleTimeout = 50 * time.Millisecond
	h1.SetIdle()

	// the idle timer should close the underlying connection
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected the connection to be closed after the idle timeout")
	}
}

func TestH1ConnResetIdleKeepsConnOpen(t *testing.T) {
	h1, server := newPipeH1Conn(t)

	h1.idleTimeout = 50 * time.Millisecond
	h1.SetIdle()
	time.Sleep(10 * time.Millisecond)
	h1.ResetIdle()

	// give the original timer time to fire; it must have been cancelled
	time.Sleep(100 * time.Millisecond)

	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected a timeout reading from a connection that is still open")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout, got: %v", err)
	}
}

func TestH1ConnCloseStopsIdleTimer(t *testing.T) {
	h1, server := newPipeH1Conn(t)

	h1.idleTimeout = 50 * time.Millisecond
	h1.SetIdle()
	if err := h1.Close(); err != nil {
		t.Fatal(err)
	}

	// wait longer than the idle timeout; the timer must not panic or
	// double-close after Close already ran
	time.Sleep(100 * time.Millisecond)

	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF after Close, got: %v", err)
	}
}
