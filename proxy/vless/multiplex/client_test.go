package multiplex_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestPoolFailure(t *testing.T) {
	calls := 0
	pool := multiplex.NewPool(context.Background(), multiplex.ClientStrategy{}, func(context.Context) (context.Context, *transport.Link, error) {
		calls++
		return nil, nil, errors.New("test")
	})
	defer pool.Close()
	if _, err := pool.PickAvailable(context.Background()); err == nil || calls != 1 {
		t.Fatalf("expected one failed opening, got %d calls and %v", calls, err)
	}
}

func TestClientWorkerEOF(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	common.Must(writer.Close())

	worker := multiplex.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, multiplex.ClientStrategy{})

	time.Sleep(time.Millisecond * 500)

	f := worker.Dispatch(context.Background(), nil, false)
	if f {
		t.Error("expected failed dispatching, but actually not")
	}
}

func TestClientWorkerClose(t *testing.T) {
	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	links := []*transport.Link{{Reader: r1, Writer: w1}, {Reader: r2, Writer: w2}}
	pool := multiplex.NewPool(context.Background(), multiplex.ClientStrategy{MaxConcurrency: 4, MaxConnection: 4}, func(ctx context.Context) (context.Context, *transport.Link, error) {
		if len(links) == 0 {
			return nil, nil, errors.New("unexpected opening")
		}
		link := links[0]
		links = links[1:]
		return ctx, link, nil
	})
	defer pool.Close()
	worker1, err := pool.PickAvailable(context.Background())
	common.Must(err)
	tr1, tw1 := pipe.New(pipe.WithoutSizeLimit())
	ctx1 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	common.Must(multiplex.Dispatch(ctx1, &transport.Link{Reader: tr1, Writer: tw1}, false, pool.PickAvailable))
	defer tw1.Close()
	common.Must(w1.Close())
	time.Sleep(time.Millisecond * 500)
	if !worker1.Closed() {
		t.Error("worker1 is not finished")
	}
	tr2, tw2 := pipe.New(pipe.WithoutSizeLimit())
	ctx2 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	common.Must(multiplex.Dispatch(ctx2, &transport.Link{Reader: tr2, Writer: tw2}, false, pool.PickAvailable))
	defer tw2.Close()
	common.Must(w2.Close())
}

func TestClientWorkerUDPSource(t *testing.T) {
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	worker := multiplex.NewClientWorker(transport.Link{Reader: downR, Writer: upW}, multiplex.ClientStrategy{})

	inR, inW := pipe.New(pipe.WithoutSizeLimit())
	outR, outW := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: inR, Writer: outW}, false) {
		t.Fatal("failed to dispatch")
	}
	b := buf.New()
	b.WriteString("query")
	common.Must(inW.WriteMultiBuffer(buf.MultiBuffer{b}))
	mb, err := upR.ReadMultiBuffer() // New frame, the session is UDP from now on
	common.Must(err)
	buf.ReleaseMulti(mb)

	srcs := []net.Destination{
		net.UDPDestination(net.ParseAddress("1.1.1.1"), 1111),
		net.UDPDestination(net.DomainAddress("example.com"), 2222),
		net.UDPDestination(net.ParseAddress("3.3.3.3"), 3333),
	}
	w := multiplex.NewResponseWriter(1, downW, protocol.TransferTypePacket)
	var got buf.MultiBuffer
	for i := range srcs {
		b := buf.New()
		b.WriteString("reply")
		b.UDP = &srcs[i]
		common.Must(w.WriteMultiBuffer(buf.MultiBuffer{b}))
		// keep earlier replies around while the next frame is parsed
		mb, err := outR.ReadMultiBuffer()
		common.Must(err)
		got = append(got, mb...)
	}
	for i, b := range got {
		if b.UDP == nil || *b.UDP != srcs[i] {
			t.Errorf("reply %d: source = %v, want %v", i, b.UDP, srcs[i])
		}
	}
}
