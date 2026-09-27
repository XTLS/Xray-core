package socks

import (
	"net"
	"testing"
	"time"
)

func TestTempUDPConnCloseJoinsItsOwnResources(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, peer := net.Pipe()
	defer peer.Close()
	c := NewTempUDPConn(udp, tcp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	c.SetTimeout(time.Minute)
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("association close deadlocked")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	var p [1]byte
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(p[:]); err == nil {
		t.Fatal("TCP control remained open")
	}
	if _, err := udp.WriteTo(p[:], udp.LocalAddr()); err == nil {
		t.Fatal("UDP association remained open")
	}
}

func TestTempUDPConnCloseBeforeTimer(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, peer := net.Pipe()
	defer peer.Close()
	c := NewTempUDPConn(udp, tcp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
