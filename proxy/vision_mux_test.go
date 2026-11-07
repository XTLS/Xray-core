package proxy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// slowWriter gives a socket write the time it takes on a real connection,
// so that a second call can come in while the first is still inside.
type slowWriter struct{ buf.Writer }

func (w slowWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	time.Sleep(time.Millisecond)
	return w.Writer.WriteMultiBuffer(mb)
}

type answeringDispatcher struct{}

func (answeringDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	inReader, inWriter := pipe.New(pipe.WithoutSizeLimit())
	outReader, outWriter := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		if _, err := inReader.ReadMultiBuffer(); err != nil {
			return
		}
		for range 4 {
			outWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))})
		}
		outWriter.Close()
	}()
	return &transport.Link{Reader: outReader, Writer: inWriter}, nil
}

func (answeringDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (answeringDispatcher) Start() error      { return nil }
func (answeringDispatcher) Close() error      { return nil }
func (answeringDispatcher) Type() interface{} { return routing.DispatcherType() }

// TestVisionUnderMux runs a mux server on top of a VisionWriter, the way the
// VLESS inbound hands its connection writer to mux.Server.DispatchLink, and
// a mux client on top of a VisionReader. Sessions answer at the same time,
// so the padding of every frame must be computed in the order the frames go
// out, or the client takes padding for frame headers.
func TestVisionUnderMux(t *testing.T) {
	uuid := []byte("0123456789abcdef")
	downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())

	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	visionWriter := proxy.NewVisionWriter(slowWriter{downWriter}, proxy.NewTrafficState(uuid), false, serverCtx, nil, nil, nil)
	_, err := mux.NewServerWorker(serverCtx, answeringDispatcher{}, &transport.Link{Reader: upReader, Writer: visionWriter})
	common.Must(err)

	visionReader := proxy.NewVisionReader(downReader, proxy.NewTrafficState(uuid), false, context.Background(), nil, nil, nil, nil)
	client, err := mux.NewClientWorker(transport.Link{Reader: visionReader, Writer: upWriter}, mux.ClientStrategy{MaxConcurrency: 32})
	common.Must(err)

	var wg sync.WaitGroup
	for i := range 32 {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.DomainAddress("example.com"), net.Port(1000+i)),
		}})
		reqReader, reqWriter := pipe.New(pipe.WithoutSizeLimit())
		respReader, respWriter := pipe.New(pipe.WithoutSizeLimit())
		reqWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))})
		if !client.Dispatch(ctx, &transport.Link{Reader: reqReader, Writer: respWriter}) {
			t.Fatal("failed to dispatch")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer reqWriter.Close()
			var got int32
			for got < 4*int32(len("response")) {
				mb, err := respReader.ReadMultiBuffer()
				if err != nil {
					t.Errorf("session %d: got %d bytes, then %v", i, got, err)
					return
				}
				got += mb.Len()
				buf.ReleaseMulti(mb)
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("sessions did not finish")
	}
	if client.Closed() {
		t.Error("mux client closed the connection, it could not parse what the server wrote")
	}
}
