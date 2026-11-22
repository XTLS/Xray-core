package taggedimpl

import (
	"context"
	"errors"
	"io"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type recordingDispatcher struct {
	routing.Dispatcher
	ctx context.Context
	err error
}

func (d *recordingDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.ctx = ctx
	if d.err != nil {
		return nil, d.err
	}
	reader, writer := pipe.New()
	return &transport.Link{Reader: reader, Writer: writer}, nil
}

func TestCloseCancelsTaggedDispatch(t *testing.T) {
	t.Parallel()
	parent := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	dispatcher := new(recordingDispatcher)
	conn, err := DialTaggedOutbound(parent, dispatcher, xnet.TCPDestination(xnet.LocalHostIP, 443), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if dispatcher.ctx.Err() != nil {
		t.Fatal("dispatch context canceled while the connection is open")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "ping" {
		t.Fatalf("unexpected payload %q", data)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if dispatcher.ctx.Err() != context.Canceled {
		t.Fatal("closing connection did not cancel dispatch")
	}
	if parent.Err() != nil {
		t.Fatal("closing connection canceled its parent")
	}
}

func TestDispatchFailureCancelsContext(t *testing.T) {
	t.Parallel()
	parent := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
	expected := errors.New("dispatch failed")
	dispatcher := &recordingDispatcher{err: expected}
	conn, err := DialTaggedOutbound(parent, dispatcher, xnet.TCPDestination(xnet.LocalHostIP, 443), "probe")
	if conn != nil || err != expected {
		t.Fatalf("unexpected result %v, %v", conn, err)
	}
	if dispatcher.ctx.Err() != context.Canceled {
		t.Fatal("failed dispatch retained its context")
	}
}

func TestTaggedDispatchInheritsParentCancellation(t *testing.T) {
	t.Parallel()
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance)))
	defer cancel()
	dispatcher := new(recordingDispatcher)
	conn, err := DialTaggedOutbound(parent, dispatcher, xnet.TCPDestination(xnet.LocalHostIP, 443), "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if dispatcher.ctx.Err() != context.Canceled {
		t.Fatal("dispatch ignored parent cancellation")
	}
}
