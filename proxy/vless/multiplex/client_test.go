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
	owner, stop := context.WithCancel(context.Background())
	defer stop()
	pool := NewPool(owner, ClientStrategy{}, func(context.Context) (context.Context, *transport.Link, error) {
		calls++
		return nil, nil, errors.New("test")
	})
	ctx := testOutboundContext()
	s := NewSession(ctx, &transport.Link{Writer: buf.Discard})
	if err := pool.Admit(ctx, s); err == nil || calls != 1 {
		t.Fatalf("expected one failed opening, got %d calls and %v", calls, err)
	}
}

func TestClientWorkerEOF(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	common.Must(writer.Close())

	worker := NewClientWorker(context.Background(), transport.Link{Reader: reader, Writer: writer}, ClientStrategy{})

	time.Sleep(time.Millisecond * 500)

	ctx := testOutboundContext()
	f := worker.TryAdmit(ctx, NewSession(ctx, &transport.Link{Writer: buf.Discard}))
	if f {
		t.Error("expected failed dispatching, but actually not")
	}
}

func TestClientWorkerClose(t *testing.T) {
	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	links := []*transport.Link{{Reader: r1, Writer: w1}, {Reader: r2, Writer: w2}}
	owner, stop := context.WithCancel(context.Background())
	defer stop()
	pool := NewPool(owner, ClientStrategy{MaxConcurrency: 4, MaxConnection: 4}, func(ctx context.Context) (context.Context, *transport.Link, error) {
		if len(links) == 0 {
			return nil, nil, errors.New("unexpected opening")
		}
		link := links[0]
		links = links[1:]
		return ctx, link, nil
	})
	ctx := testOutboundContext()
	worker1 := NewSession(ctx, &transport.Link{Writer: buf.Discard})
	common.Must(pool.Admit(ctx, worker1))
	tr1, tw1 := pipe.New(pipe.WithoutSizeLimit())
	ctx1 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	child1 := NewSession(ctx1, &transport.Link{Reader: tr1, Writer: tw1})
	common.Must(pool.Admit(ctx1, child1))
	go fetchInput(ctx1, child1)
	defer tw1.Close()
	common.Must(w1.Close())
	time.Sleep(time.Millisecond * 500)
	if !worker1.parent.Closed() {
		t.Error("worker1 is not finished")
	}
	tr2, tw2 := pipe.New(pipe.WithoutSizeLimit())
	ctx2 := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("www.example.com"), 80)}})
	child2 := NewSession(ctx2, &transport.Link{Reader: tr2, Writer: tw2})
	common.Must(pool.Admit(ctx2, child2))
	go fetchInput(ctx2, child2)
	defer tw2.Close()
	common.Must(w2.Close())
}

func TestClientWorkerUDPSource(t *testing.T) {
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	worker := NewClientWorker(context.Background(), transport.Link{Reader: downR, Writer: upW}, ClientStrategy{})

	inR, inW := pipe.New(pipe.WithoutSizeLimit())
	outR, outW := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.ParseAddress("8.8.8.8"), 53),
	}})
	child := NewSession(ctx, &transport.Link{Reader: inR, Writer: outW})
	if !worker.TryAdmit(ctx, child) {
		t.Fatal("failed to dispatch")
	}
	defer worker.Close()
	go fetchInput(ctx, child)
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
	response := &Session{ID: 1, transferType: protocol.TransferTypePacket}
	var got buf.MultiBuffer
	for i := range srcs {
		b := buf.New()
		b.WriteString("reply")
		b.UDP = &srcs[i]
		data := buf.MultiBuffer{b}
		frames, err := response.encodeBatch(&data)
		buf.ReleaseMulti(data)
		if err != nil {
			buf.ReleaseMulti(frames)
			t.Fatal(err)
		}
		common.Must(downW.WriteMultiBuffer(frames))
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
