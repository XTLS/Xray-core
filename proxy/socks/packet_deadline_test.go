package socks

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTempUDPWriteDeadlinePreservesAssociation(t *testing.T) {
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control, client := net.Pipe()
	defer client.Close()
	conn := NewTempUDPConn(socket, control, peer.LocalAddr().(*net.UDPAddr))
	conn.SetTimeout(time.Minute)
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("expired")); err == nil {
		t.Fatal("expired write was accepted")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("next leg")); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	p := make([]byte, 32)
	n, _, err := peer.ReadFrom(p)
	if err != nil || string(p[:n]) != "next leg" {
		t.Fatalf("reply=%q err=%v", p[:n], err)
	}
	conn.Close()
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(p); err != io.EOF {
		t.Fatalf("control did not close with association: %v", err)
	}
}
