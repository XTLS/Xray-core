package outbound

import (
	"context"
	"io"
	gonet "net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type muxTestDialer struct{ conn gonet.Conn }

func (d muxTestDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func (muxTestDialer) DestIpAddress() net.IP                                 { return nil }
func (muxTestDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

type muxBlockedConn struct {
	gonet.Conn
	entered chan string
	result  chan error
}

func (c *muxBlockedConn) Write(p []byte) (int, error) {
	stack := make([]byte, 8192)
	c.entered <- string(stack[:runtime.Stack(stack, false)])
	n, err := c.Conn.Write(p)
	c.result <- err
	return n, err
}

func TestDirectMuxCloseInterruptsPhysicalWrite(t *testing.T) {
	raw, peer := gonet.Pipe()
	t.Cleanup(func() {
		raw.Close()
		peer.Close()
	})
	conn := &muxBlockedConn{Conn: raw, entered: make(chan string, 1), result: make(chan error, 1)}
	handler := &Handler{
		server: protocol.NewServerSpec(net.TCPDestination(net.DomainAddress("vless.test"), 443), &protocol.MemoryUser{
			Account: &vless.MemoryAccount{ID: protocol.NewID(uuid.New())},
		}),
		policyManager: policy.DefaultManager{},
	}
	worker, err := (&muxWorkerFactory{handler: handler, dialer: muxTestDialer{conn: conn}}).Create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close() })

	input, client := pipe.New()
	output, reply := pipe.New()
	t.Cleanup(func() {
		client.Interrupt()
		reply.Interrupt()
	})
	mb := buf.New()
	mb.Extend(1)
	if err := client.WriteMultiBuffer(buf.MultiBuffer{mb}); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("target.test"), 80),
	}})
	if !worker.Dispatch(ctx, &transport.Link{Reader: input, Writer: reply}) {
		t.Fatal("worker rejected session")
	}

	const timeout = 3 * time.Second
	select {
	case stack := <-conn.entered:
		if !strings.Contains(stack, "/common/mux.fetchInput(") {
			t.Fatalf("first frame did not reach the transport directly:\n%s", stack)
		}
	case <-time.After(timeout):
		t.Fatal("no first frame reached the transport")
	}
	// The peer has never read. Closing the carrier must wake the blocked write.
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-conn.result:
		if err == nil {
			t.Fatal("transport write succeeded without a reader")
		}
	case <-time.After(timeout):
		t.Fatal("transport write remained blocked after worker close")
	}
	if mb, err := output.ReadMultiBufferTimeout(timeout); err != io.EOF {
		buf.ReleaseMulti(mb)
		t.Fatalf("logical session did not close: %v", err)
	}
}

type muxFinalReader struct{ reads int }

func (r *muxFinalReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.reads++
	b := buf.New()
	b.WriteByte(42)
	return buf.MultiBuffer{b}, io.EOF
}

func TestDirectMuxReadDeliversFinalBatchBeforeEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := new(muxFinalReader)
	carrier := &muxCarrier{ctx: ctx, cancel: cancel, reader: source, activity: new(signal.ActivityTimer)}
	reader := &buf.BufferedReader{Reader: carrier}
	var b [1]byte
	if _, err := io.ReadFull(reader, b[:]); err != nil || b[0] != 42 {
		t.Fatalf("lost final byte: %v, %v", b, err)
	}
	if ctx.Err() != nil {
		t.Fatal("carrier stopped before final bytes reached its consumer")
	}
	if _, err := reader.Read(b[:]); err != io.EOF || source.reads != 1 || ctx.Err() == nil {
		t.Fatalf("terminal read: error %v, source reads %d, context %v", err, source.reads, ctx.Err())
	}
}

type muxPreconnectDialer struct {
	muxTestDialer
	started chan struct{}
	resume  chan struct{}
}

func (d muxPreconnectDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	close(d.started)
	<-d.resume
	return d.conn, nil
}

func TestCloseReclaimsInFlightPreconnection(t *testing.T) {
	raw, peer := gonet.Pipe()
	t.Cleanup(func() {
		raw.Close()
		peer.Close()
	})
	dialer := muxPreconnectDialer{
		muxTestDialer: muxTestDialer{conn: raw},
		started:       make(chan struct{}),
		resume:        make(chan struct{}, 1),
	}
	t.Cleanup(func() { close(dialer.resume) })
	h := &Handler{server: &protocol.ServerSpec{}, testpre: 1}
	t.Cleanup(func() { h.Close() })

	// A canceled consumer leaves the preconnect producer responsible for any
	// connection returned by a dial that completes during handler shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.takePreconnected(ctx, dialer); err != context.Canceled {
		t.Fatalf("preconnect wait returned %v", err)
	}
	const timeout = 3 * time.Second
	select {
	case <-dialer.started:
	case <-time.After(timeout):
		t.Fatal("preconnect did not start")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	dialer.resume <- struct{}{}
	if err := peer.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection returned after shutdown was not closed: %v", err)
	}

	closedBeforeInit := &Handler{testpre: 1}
	if err := closedBeforeInit.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := closedBeforeInit.takePreconnected(context.Background(), dialer); err != io.ErrClosedPipe {
		t.Fatalf("closed handler allowed preconnect initialization: %v", err)
	}
}
