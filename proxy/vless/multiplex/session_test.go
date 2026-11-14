package multiplex

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal/done"
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
	s := &Session{ID: 4, parent: worker.carrier, output: buf.Discard, done: done.New(), phase: outputOpen, transferType: protocol.TransferTypeStream}
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
	worker := NewClientWorker(context.Background(), transport.Link{Reader: reader, Writer: buf.Discard}, ClientStrategy{})
	t.Cleanup(func() { worker.Close(); writer.Close() })
	ctx := testOutboundContext()
	s := NewSession(ctx, &transport.Link{Writer: buf.Discard})
	if !worker.TryAdmit(ctx, s) {
		t.Fatal("session not admitted")
	}
	worker.timer.Reset(5 * time.Millisecond)
	select {
	case <-worker.WaitClosed():
		t.Fatal("active carrier retired")
	case <-time.After(25 * time.Millisecond):
	}
	s.Close()
	select {
	case <-worker.WaitClosed():
	case <-time.After(time.Second):
		t.Fatal("empty carrier did not retire")
	}
}
