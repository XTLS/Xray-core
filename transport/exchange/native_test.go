package exchange

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	s.SetDeadline(time.Now().Add(3 * time.Second))
	return c, s
}

func TestNativeTransferProgressReplayAndEOF(t *testing.T) {
	for _, splice := range []bool{false, true} {
		t.Run(map[bool]string{false: "vector", true: "splice"}[splice], func(t *testing.T) {
			sender, source := tcpPair(t)
			target, receiver := tcpPair(t)
			payload := bytes.Repeat([]byte("data"), 65536)
			input := NewInput(source, nil)
			input.cached = []byte("prefix")
			var read, written atomic.Int64
			done := make(chan error, 1)
			go func() {
				done <- transfer(target, input, true, splice, func() {}, func(n int64) { read.Add(n) }, func(n int64) { written.Add(n) })
			}()
			sent := make(chan error, 1)
			go func() { _, err := sender.Write(payload); sent <- err }()
			reply := make([]byte, len(payload)+6)
			if _, err := io.ReadFull(receiver, reply); err != nil {
				t.Fatal(err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for written.Load() != int64(len(reply)) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !bytes.Equal(reply, append([]byte("prefix"), payload...)) || read.Load() != int64(len(reply)) || written.Load() != int64(len(reply)) {
				t.Fatalf("replay/progress read=%d write=%d", read.Load(), written.Load())
			}
			select {
			case err := <-done:
				t.Fatalf("ended before EOF: %v", err)
			default:
			}
			sender.CloseWrite()
			select {
			case err := <-done:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("terminal=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("raw EOF not joined")
			}
		})
	}
}
