package inbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	stdnet "net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless/encryption"
)

type stubPolicyManager struct {
	handshake time.Duration
}

func (stubPolicyManager) Type() interface{}        { return policy.ManagerType() }
func (stubPolicyManager) Start() error             { return nil }
func (stubPolicyManager) Close() error             { return nil }
func (stubPolicyManager) ForSystem() policy.System { return policy.System{} }
func (m stubPolicyManager) ForLevel(uint32) policy.Session {
	return policy.Session{
		Timeouts: policy.Timeout{
			Handshake: m.handshake,
		},
	}
}

type deadlineInspectConn struct {
	stdnet.Conn
	mu                  sync.Mutex
	deadlineOnFirstRead time.Time
	readCalled          bool
}

func (c *deadlineInspectConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	if !c.readCalled {
		c.deadlineOnFirstRead = t
	}
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineInspectConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.readCalled = true
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func TestProcessSetsHandshakeDeadlineBeforeDecryptionHandshake(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dec := &encryption.ServerInstance{}
	if err := dec.Init([][]byte{priv.Bytes()}, 0, 0, 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dec.Close() })

	serverPipe, clientPipe := stdnet.Pipe()
	t.Cleanup(func() {
		_ = serverPipe.Close()
		_ = clientPipe.Close()
	})

	conn := &deadlineInspectConn{Conn: serverPipe}
	h := &Handler{
		policyManager: stubPolicyManager{handshake: 50 * time.Millisecond},
		decryption:    dec,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(context.Background(), net.Network_TCP, conn, nil)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected handshake timeout error from silent peer, got nil")
		}
		var netErr stdnet.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
			t.Fatalf("expected deadline/timeout error, got %v", err)
		}
		conn.mu.Lock()
		firstDeadline := conn.deadlineOnFirstRead
		conn.mu.Unlock()
		if firstDeadline.IsZero() {
			t.Fatal("expected read deadline to be set before decryption handshake reads")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Process blocked past handshake timeout when decryption was enabled")
	}
}

func TestProcessHandshakeTimeoutWithoutDecryption(t *testing.T) {
	serverPipe, clientPipe := stdnet.Pipe()
	t.Cleanup(func() {
		_ = serverPipe.Close()
		_ = clientPipe.Close()
	})

	h := &Handler{
		policyManager: stubPolicyManager{handshake: 50 * time.Millisecond},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Process(context.Background(), net.Network_TCP, serverPipe, nil)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected handshake timeout error from silent peer, got nil")
		}
		var netErr stdnet.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
			t.Fatalf("expected deadline/timeout error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Process blocked past handshake timeout")
	}
}
