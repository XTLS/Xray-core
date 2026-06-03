package rawpacket

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type mockSpoofer struct {
	mu        sync.Mutex
	calls     []string
	injectErr error
	closeErr  error
}

func (m *mockSpoofer) Inject([]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "inject")
	return m.injectErr
}

func (m *mockSpoofer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "close")
	return m.closeErr
}

func (m *mockSpoofer) callOrder() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

type recordingConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dup := make([]byte, len(b))
	copy(dup, b)
	c.writes = append(c.writes, dup)
	return len(b), nil
}
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingConn) wrotePayloads() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	for i, w := range c.writes {
		dup := make([]byte, len(w))
		copy(dup, w)
		out[i] = dup
	}
	return out
}

func TestWriteCallOrder(t *testing.T) {
	spoofer := &mockSpoofer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = io.ReadAll(server)
	}()

	conn := &Conn{
		Conn:          client,
		spoofer:       spoofer,
		fakePayload:   []byte("fake"),
		maxInjections: 1,
	}

	if _, err := conn.Write([]byte("real")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	order := spoofer.callOrder()
	if len(order) != 2 || order[0] != "inject" || order[1] != "close" {
		t.Fatalf("call order = %v, want [inject close]", order)
	}
}

func TestWriteCloseAfterUnderlyingWrite(t *testing.T) {
	spoofer := &mockSpoofer{}
	rec := &recordingConn{}
	conn := &Conn{
		Conn:          rec,
		spoofer:       spoofer,
		fakePayload:   []byte("fake"),
		maxInjections: 1,
	}

	if _, err := conn.Write([]byte("real")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(rec.wrotePayloads()) != 1 {
		t.Fatalf("expected one underlying write, got %d", len(rec.wrotePayloads()))
	}
	if order := spoofer.callOrder(); len(order) != 2 || order[1] != "close" {
		t.Fatalf("close not last: %v", order)
	}
}

func TestBuildFakeClientHello(t *testing.T) {
	hello, err := BuildFakeClientHello("hcaptcha.com")
	if err != nil {
		t.Fatalf("buildFakeClientHello: %v", err)
	}
	if len(hello) == 0 {
		t.Fatal("empty ClientHello")
	}
	if hello[0] != 0x16 {
		t.Fatalf("expected TLS handshake record (0x16), got 0x%x", hello[0])
	}
}

func TestBuildFakeClientHelloEmptySNI(t *testing.T) {
	_, err := BuildFakeClientHello("")
	if err == nil {
		t.Fatal("expected error for empty sni")
	}
}

type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write([]byte) (int, error)        { return 0, errors.New("unexpected write") }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return nil }
func (discardConn) RemoteAddr() net.Addr             { return nil }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }
