//go:build linux || android

package proxy

import (
	"net"
	"testing"
	"time"
)

func TestTCPBytesReceived(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("hello"))
		time.Sleep(50 * time.Millisecond)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var n int64
	ok := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, ok = tcpBytesReceived(c)
		if ok && n >= 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	<-done
	if !ok {
		t.Fatal("tcpBytesReceived failed")
	}
	if n < 5 {
		t.Fatalf("bytes received = %d, want >= 5", n)
	}
}
