package multiplex

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestCarrierAdmission(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	worker := NewClientWorker(context.Background(), transport.Link{Reader: reader, Writer: buf.Discard}, ClientStrategy{})
	t.Cleanup(func() { worker.Close(); writer.Close() })
	for id := uint16(1); id <= 2; id++ {
		ctx := testOutboundContext()
		s := NewSession(ctx, &transport.Link{Writer: buf.Discard})
		if !worker.TryAdmit(ctx, s) || s.ID != id {
			t.Fatalf("id%d: %v", id, s)
		}
		if worker.ActiveConnections() != uint32(id) {
			t.Fatalf("active: %d", worker.ActiveConnections())
		}
	}
	// Preserve the original explicit-ID publication assertion, with a fully
	// initialized real physical owner instead of a standalone manager facade.
	s := &Session{ID: 4, parent: worker.carrier, output: buf.Discard, done: make(chan struct{}), phase: outputOpen}
	worker.Lock()
	admitted := worker.admitLocked(s)
	indexed := worker.sessions[4] == s
	worker.Unlock()
	if !admitted || !indexed || s.ID != 4 || worker.ActiveConnections() != 3 {
		t.Fatal("explicit wire identity not admitted")
	}
}

func TestCarrierIdleRetirement(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	worker := &ClientWorker{carrier: newCarrier(context.Background(), transport.Link{Reader: reader, Writer: buf.Discard}, 20*time.Millisecond, true)}
	go worker.run(context.Background(), nil)
	t.Cleanup(func() { worker.Close(); writer.Close() })
	ctx := testOutboundContext()
	s := NewSession(ctx, &transport.Link{Writer: buf.Discard})
	if !worker.TryAdmit(ctx, s) {
		t.Fatal("session not admitted")
	}
	select {
	case <-worker.WaitClosed():
		t.Fatal("active carrier retired")
	case <-time.After(65 * time.Millisecond):
	}
	s.Close()
	select {
	case <-worker.WaitClosed():
	case <-time.After(time.Second):
		t.Fatal("empty carrier did not retire")
	}
}
