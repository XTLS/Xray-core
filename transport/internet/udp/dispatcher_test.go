package udp_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

type TestDispatcher struct {
	OnDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *TestDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.OnDispatch(ctx, dest)
}

func (d *TestDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	return nil
}

func (d *TestDispatcher) Start() error {
	return nil
}

func (d *TestDispatcher) Close() error {
	return nil
}

func (*TestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func TestSameDestinationDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1024))

	go func() {
		for {
			data, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				break
			}
			err = downlinkWriter.WriteMultiBuffer(data)
			common.Must(err)
		}
	}()

	var count uint32
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dest := net.UDPDestination(net.LocalHostIP, 53)

	b := buf.New()
	b.WriteString("abcd")

	var msgCount uint32
	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {
		atomic.AddUint32(&msgCount, 1)
	})

	dispatcher.Dispatch(ctx, dest, b)
	for i := 0; i < 5; i++ {
		dispatcher.Dispatch(ctx, dest, b)
	}

	time.Sleep(time.Second)
	cancel()

	if count != 1 {
		t.Error("count: ", count)
	}
	if v := atomic.LoadUint32(&msgCount); v != 6 {
		t.Error("msgCount: ", v)
	}
}

func TestIdleTimeout(t *testing.T) {
	var count uint32
	var uplinkReaders []*pipe.Reader
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024))
			downlinkReader, _ := pipe.New(pipe.WithSizeLimit(1024)) // the remote never answers
			uplinkReaders = append(uplinkReaders, uplinkReader)
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dest := net.UDPDestination(net.LocalHostIP, 53)
	newPayload := func() *buf.Buffer {
		b := buf.New()
		b.WriteString("abcd")
		return b
	}

	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {})
	dispatcher.SetIdleTimeout(200 * time.Millisecond)
	dispatcher.Dispatch(context.Background(), dest, newPayload())

	// The flow ends once it has waited the idle timeout for a response,
	// which interrupts its link.
	done := make(chan struct{})
	go func() {
		for {
			if _, err := uplinkReaders[0].ReadMultiBuffer(); err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("flow still alive 5 s after its 200 ms idle timeout")
	}

	// The next datagram starts a new flow.
	time.Sleep(100 * time.Millisecond)
	dispatcher.Dispatch(context.Background(), dest, newPayload())
	if v := atomic.LoadUint32(&count); v != 2 {
		t.Error("count: ", v)
	}
	dispatcher.RemoveRay()
}

func TestDefaultIdleTimeout(t *testing.T) {
	var count uint32
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			atomic.AddUint32(&count, 1)
			_, uplinkWriter := pipe.New(pipe.WithSizeLimit(1024), pipe.DiscardOverflow())
			downlinkReader, _ := pipe.New(pipe.WithSizeLimit(1024))
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dest := net.UDPDestination(net.LocalHostIP, 53)

	dispatcher := NewDispatcher(td, func(ctx context.Context, packet *udp.Packet) {})
	dispatcher.SetIdleTimeout(0) // keeps the default of one minute
	for i := 0; i < 2; i++ {
		b := buf.New()
		b.WriteString("abcd")
		dispatcher.Dispatch(context.Background(), dest, b)
		time.Sleep(500 * time.Millisecond)
	}
	if v := atomic.LoadUint32(&count); v != 1 {
		t.Error("count: ", v)
	}
	dispatcher.RemoveRay()
}
