package multiplex

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
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestPoolFailure(t *testing.T) {
	calls := 0
	pool := NewPool(context.Background(), ClientStrategy{}, func(context.Context) (context.Context, *transport.Link, error) {
		calls++
		return nil, nil, errors.New("test")
	})
	defer pool.Close()
	if _, err := pool.Admit(testOutboundContext(), &transport.Link{Writer: buf.Discard}); err == nil || calls != 1 {
		t.Fatalf("expected one failed opening, got %d calls and %v", calls, err)
	}
}

func TestClientWorkerEOF(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	common.Must(writer.Close())

	worker := NewClientWorker(transport.Link{Reader: reader, Writer: writer}, ClientStrategy{})

	time.Sleep(time.Millisecond * 500)

	f := worker.TryAdmit(context.Background(), nil) != nil
	if f {
		t.Error("expected failed dispatching, but actually not")
	}
}

func TestClientWorkerClose(t *testing.T) {
	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	links := []*transport.Link{{Reader: r1, Writer: w1}, {Reader: r2, Writer: w2}}
	pool := NewPool(context.Background(), ClientStrategy{MaxConcurrency: 4, MaxConnection: 4}, func(ctx context.Context) (context.Context, *transport.Link, error) {
		if len(links) == 0 {
			return nil, nil, errors.New("unexpected opening")
		}
		link := links[0]
		links = links[1:]
		return ctx, link, nil
	})
	defer pool.Close()
	worker1, err := pool.Admit(testOutboundContext(), &transport.Link{Writer: buf.Discard})
	common.Must(err)
	tr1, tw1 := pipe.New(pipe.WithoutSizeLimit())
	ctx1 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	common.Must(Dispatch(ctx1, &transport.Link{Reader: tr1, Writer: tw1}, false, pool.Admit))
	defer tw1.Close()
	common.Must(w1.Close())
	time.Sleep(time.Millisecond * 500)
	if !worker1.sender.Closed() {
		t.Error("worker1 is not finished")
	}
	tr2, tw2 := pipe.New(pipe.WithoutSizeLimit())
	ctx2 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	common.Must(Dispatch(ctx2, &transport.Link{Reader: tr2, Writer: tw2}, false, pool.Admit))
	defer tw2.Close()
	common.Must(w2.Close())
}

func TestClientWorkerUDPSource(t *testing.T) {
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	worker := NewClientWorker(transport.Link{Reader: downR, Writer: upW}, ClientStrategy{})

	inR, inW := pipe.New(pipe.WithoutSizeLimit())
	outR, outW := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53),
	}})
	if err := Dispatch(ctx, &transport.Link{Reader: inR, Writer: outW}, false, testWorkerAdmission(worker)); err != nil {
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
	w := NewResponseWriter(1, downW, protocol.TransferTypePacket)
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

func testOutboundContext() context.Context {
	return session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
}

func testWorkerAdmission(worker *ClientWorker) func(context.Context, *transport.Link) (*Session, error) {
	return func(ctx context.Context, link *transport.Link) (*Session, error) {
		s := worker.TryAdmit(ctx, link)
		if s == nil {
			return nil, errors.New("unable to admit test child")
		}
		return s, nil
	}
}
