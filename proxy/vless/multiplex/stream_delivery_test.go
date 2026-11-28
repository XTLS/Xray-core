package multiplex

import (
	"context"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
)

type streamDeliveryDispatcher struct {
	routing.Dispatcher
	dispatch func(*transport.Link) error
}

func (d streamDeliveryDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	return d.dispatch(link)
}

type streamDeliveryWriter struct {
	write func(buf.MultiBuffer) error
}

func (w streamDeliveryWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	return w.write(packets)
}

func TestStreamDeliveryKeepsMuxSiblingReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, peer := stdnet.Pipe()
	defer peer.Close()
	writeStarted := make(chan struct{})
	release := make(chan struct{})
	closeRoute := make(chan struct{})
	linkReady := make(chan *transport.Link, 1)
	finished := make(chan error, 1)
	var first sync.Once
	delivered := make(chan string, 3)

	go func() {
		finished <- proxy.DispatchInboundStream(ctx, conn, policy.Session{
			Buffer:   policy.Buffer{PerConnection: 128},
			Timeouts: policy.Timeout{ConnectionIdle: 3 * time.Second, UplinkOnly: time.Second, DownlinkOnly: time.Second},
		}, streamDeliveryDispatcher{dispatch: func(link *transport.Link) error {
			linkReady <- link
			select {
			case <-closeRoute:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}, net.TCPDestination(net.LocalHostIP, 10001), buf.NewReader(conn),
			streamDeliveryWriter{write: func(packets buf.MultiBuffer) error {
				first.Do(func() { close(writeStarted) })
				select {
				case <-release:
					for _, b := range packets {
						delivered <- string(b.Bytes())
					}
					return nil
				case <-ctx.Done():
					return io.ErrClosedPipe
				}
			}},
			nil)
	}()

	var link *transport.Link
	select {
	case link = <-linkReady:
	case <-ctx.Done():
		t.Fatal("stream endpoint was not supplied")
	}
	shared := &carrier{}
	slow := &Session{parent: shared, phase: outputOpen, output: link.Writer}
	sibling := &Session{parent: shared, phase: outputOpen, output: streamDeliveryWriter{write: func(buf.MultiBuffer) error { return nil }}}
	muxDone := make(chan error, 1)
	go func() {
		for _, text := range []string{"first", "second", "third"} {
			if err := slow.writePayload(buf.MultiBuffer{buf.FromBytes([]byte(text))}); err != nil {
				muxDone <- err
				return
			}
		}
		muxDone <- sibling.writePayload(buf.MultiBuffer{buf.FromBytes([]byte("sibling"))})
	}()
	select {
	case <-writeStarted:
	case <-ctx.Done():
		t.Fatal("first physical write did not start")
	}
	select {
	case err := <-muxDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("slow child blocked the sibling before the connection budget filled")
	}

	close(release)
	close(closeRoute)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("route did not drain after healthy close")
	}
	for _, want := range []string{"first", "second", "third"} {
		select {
		case got := <-delivered:
			if got != want {
				t.Fatalf("drained %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing %q after normal close", want)
		}
	}
}
