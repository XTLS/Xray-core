package trojan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type trojanTestDispatcher struct {
	routing.Dispatcher
	legacyCalls  atomic.Int32
	dispatchLink func(context.Context, net.Destination, *transport.Link) error
}

func (d *trojanTestDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	d.legacyCalls.Add(1)
	return nil, errors.New("Trojan UDP called the old dispatcher")
}

func (d *trojanTestDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return d.dispatchLink(ctx, dest, link)
}

type trojanUDPTestPacket struct {
	dest net.Destination
	data string
}

func writeTrojanUDPTestPacket(writer buf.Writer, packet trojanUDPTestPacket) error {
	b := buf.New()
	if packet.dest.IsValid() {
		b.UDP = &packet.dest
	}
	if _, err := b.WriteString(packet.data); err != nil {
		b.Release()
		return err
	}
	return writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

func readTrojanUDPTestPacket(reader buf.Reader, want trojanUDPTestPacket) error {
	mb, err := reader.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil {
		return err
	}
	if len(mb) != 1 || mb[0].UDP == nil {
		return fmt.Errorf("expected one datagram with destination, got %d buffers", len(mb))
	}
	if *mb[0].UDP != want.dest || string(mb[0].Bytes()) != want.data {
		return fmt.Errorf("got %q at %s, want %q at %s", mb[0].Bytes(), *mb[0].UDP, want.data, want.dest)
	}
	return nil
}

func trojanTestTCPPair(t *testing.T, ctx context.Context) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	deadline, _ := ctx.Deadline()
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return client, conn
}

func openTrojanTestClient(t *testing.T, ctx context.Context, dispatcher routing.Dispatcher) (*net.TCPConn, *ConnWriter, <-chan error) {
	t.Helper()
	client, conn := trojanTestTCPPair(t, ctx)
	header, done := serveTrojanTest(t, ctx, conn, dispatcher)
	return client, header, done
}

func serveTrojanTest(t *testing.T, ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) (*ConnWriter, <-chan error) {
	t.Helper()
	account, err := (&Account{Password: "test-udp"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{policyManager: policy.DefaultManager{}, validator: new(Validator)}
	if err := server.AddUser(ctx, &protocol.MemoryUser{Email: "udp-test", Account: account}); err != nil {
		t.Fatal(err)
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: net.DestinationFromAddr(conn.RemoteAddr())})
	done := make(chan error, 1)
	go func() {
		done <- server.Process(ctx, net.Network_TCP, conn, dispatcher)
	}()
	return &ConnWriter{Account: account.(*MemoryAccount)}, done
}

func TestTrojanUDPDispatchLink(t *testing.T) {
	a := net.UDPDestination(net.LocalHostIP, 10001)
	b := net.UDPDestination(net.LocalHostIP, 10002)
	packets := []trojanUDPTestPacket{{a, "first"}, {b, "alternate"}, {a, "original"}}
	for _, cancelSession := range []bool{false, true} {
		name := "peer closes"
		if cancelSession {
			name = "parent cancels"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			waitingForPacket := make(chan struct{})
			firstLegDone := make(chan struct{})
			var calls atomic.Int32
			outboundDone := make(chan error, 1)
			dispatcher := &trojanTestDispatcher{dispatchLink: func(routeCtx context.Context, dest net.Destination, link *transport.Link) (err error) {
				if dest != a {
					return fmt.Errorf("route destination = %s, want %s", dest, a)
				}
				switch calls.Add(1) {
				case 1:
					context.AfterFunc(routeCtx, func() { close(firstLegDone) })
					for i := 0; i < len(packets); {
						batch, err := link.Reader.ReadMultiBuffer()
						defer buf.ReleaseMulti(batch)
						if err != nil {
							return err
						}
						for _, b := range batch {
							if i >= len(packets) {
								return errors.New("outbound received an extra packet")
							}
							pkt := packets[i]
							if b.UDP == nil || *b.UDP != pkt.dest || string(b.Bytes()) != pkt.data {
								return fmt.Errorf("unexpected packet at index %d: %q", i, b.Bytes())
							}
							if i == 2 {
								pkt.dest = net.Destination{}
							}
							if err := writeTrojanUDPTestPacket(link.Writer, pkt); err != nil {
								return err
							}
							i++
						}
					}
					// Simulate the outbound ending the first route while the
					// authenticated Trojan carrier remains open.
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					return nil
				case 2:
					defer func() { outboundDone <- err }()
					if err := readTrojanUDPTestPacket(link.Reader, trojanUDPTestPacket{b, "after retirement"}); err != nil {
						return err
					}
					if err := writeTrojanUDPTestPacket(link.Writer, trojanUDPTestPacket{data: "second route"}); err != nil {
						return err
					}
				default:
					return errors.New("started an unexpected route")
				}
				close(waitingForPacket)
				mb, err := link.Reader.ReadMultiBuffer()
				defer buf.ReleaseMulti(mb)
				if len(mb) != 0 || err == nil {
					return fmt.Errorf("terminal read returned %d buffers and error %v", len(mb), err)
				}
				return nil
			}}
			client, header, processDone := openTrojanTestClient(t, ctx, dispatcher)
			var request bytes.Buffer
			header.Target, header.Writer = a, &request
			writer := &PacketWriter{Writer: header}
			for _, pkt := range packets {
				if err := writeTrojanUDPTestPacket(writer, pkt); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client.Write(request.Bytes()); err != nil {
				t.Fatal(err)
			}
			reader := &PacketReader{Reader: client}
			replies := []trojanUDPTestPacket{packets[0], packets[1], {b, packets[2].data}}
			for _, pkt := range replies {
				if err := readTrojanUDPTestPacket(reader, pkt); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-firstLegDone:
			case <-ctx.Done():
				t.Fatal("first route did not retire")
			}
			if err := writeTrojanUDPTestPacket(&PacketWriter{Writer: client}, trojanUDPTestPacket{b, "after retirement"}); err != nil {
				t.Fatal(err)
			}
			if err := readTrojanUDPTestPacket(reader, trojanUDPTestPacket{a, "second route"}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-waitingForPacket:
			case <-ctx.Done():
				t.Fatal("outbound did not enter the terminal read")
			}
			if cancelSession {
				cancel()
			} else if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-outboundDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("outbound stayed blocked")
			}
			select {
			case <-processDone:
			case <-time.After(time.Second):
				t.Fatal("Trojan Process stayed blocked")
			}
			if calls := dispatcher.legacyCalls.Load(); calls != 0 {
				t.Fatalf("old Dispatch called %d times", calls)
			}
		})
	}
}

func TestTrojanUDPUplinkCountersSurviveRedispatch(t *testing.T) {
	first := buf.New()
	first.WriteString("first")
	second := buf.New()
	second.WriteString("second packet")
	input := udp.NewPacketInbox(0)
	defer input.Close()
	if err := input.Put(context.Background(), buf.MultiBuffer{second}); err != nil {
		t.Fatal(err)
	}
	route := &udpRoute{
		ctx:   context.Background(),
		flow:  &udpFlow{input: input},
		first: buf.MultiBuffer{first},
	}
	input.AttachRoute(route.ctx)
	counter := new(stats.Counter)
	route.SetUplinkCounter(counter)
	route.SetUplinkCounter(counter)
	route.SetUplinkCounter(nil)
	// The first dispatch counts both attempted inputs; Loopback counts
	// each record when its reader takes it.
	if got, want := counter.Value(), int64(len("firstsecond packet")); got != want {
		t.Fatalf("before reading, the redispatched uplink counter = %d, want %d", got, want)
	}

	for range 2 {
		mb, err := route.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err != nil {
			t.Fatal(err)
		}
	}
	if got, want := counter.Value(), int64(2*len("firstsecond packet")); got != want {
		t.Fatalf("redispatched uplink counter = %d, want %d", got, want)
	}
}

func TestTrojanUDPSniffTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dest := net.UDPDestination(net.LocalHostIP, 10001)
	first := trojanUDPTestPacket{dest, "initial"}
	next := trojanUDPTestPacket{dest, "partial frame"}
	partialSent := make(chan struct{})
	timedRead := make(chan error, 1)
	dispatcher := &trojanTestDispatcher{dispatchLink: func(routeCtx context.Context, _ net.Destination, link *transport.Link) error {
		reader, ok := link.Reader.(buf.TimeoutReader)
		if !ok {
			err := errors.New("UDP link lacks a timed read for sniffing")
			timedRead <- err
			return err
		}
		if err := readTrojanUDPTestPacket(link.Reader, first); err != nil {
			timedRead <- err
			return err
		}
		select {
		case <-partialSent:
		case <-routeCtx.Done():
			return routeCtx.Err()
		}
		mb, err := reader.ReadMultiBufferTimeout(20 * time.Millisecond)
		if len(mb) != 0 || !errors.Is(err, buf.ErrReadTimeout) {
			err = fmt.Errorf("incomplete frame yielded %d buffers and error %v", len(mb), err)
		} else {
			err = nil
		}
		buf.ReleaseMulti(mb)
		timedRead <- err
		if err != nil {
			return err
		}
		if err := readTrojanUDPTestPacket(link.Reader, next); err != nil {
			return err
		}
		return writeTrojanUDPTestPacket(link.Writer, next)
	}}
	client, header, processDone := openTrojanTestClient(t, ctx, dispatcher)
	var request bytes.Buffer
	header.Target, header.Writer = dest, &request
	if err := writeTrojanUDPTestPacket(&PacketWriter{Writer: header}, first); err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := writeTrojanUDPTestPacket(&PacketWriter{Writer: &frame}, next); err != nil {
		t.Fatal(err)
	}
	prefix := frame.Len() - 1
	request.Write(frame.Next(prefix))
	if _, err := client.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	close(partialSent)
	select {
	case err := <-timedRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("dispatch did not complete its sniff read")
	}
	if _, err := client.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := readTrojanUDPTestPacket(&PacketReader{Reader: client}, next); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-processDone:
	case <-ctx.Done():
		t.Fatal("Trojan Process stayed blocked")
	}
}

type trojanTestConn struct {
	net.Conn
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (c trojanTestConn) Read(data []byte) (int, error) {
	if c.read != nil {
		return c.read(data)
	}
	return c.Conn.Read(data)
}

func (c trojanTestConn) Write(data []byte) (int, error) {
	if c.write != nil {
		return c.write(data)
	}
	return c.Conn.Write(data)
}

func writeTrojanUDPTestRequest(client net.Conn, header *ConnWriter, packet trojanUDPTestPacket) error {
	var request bytes.Buffer
	header.Target, header.Writer = packet.dest, &request
	if err := writeTrojanUDPTestPacket(&PacketWriter{Writer: header}, packet); err != nil {
		return err
	}
	_, err := client.Write(request.Bytes())
	return err
}

func TestTrojanUDPSlowReplyKeepsMuxSiblingProgress(t *testing.T) {
	t.Run("reply succeeds", func(t *testing.T) { testTrojanUDPSlowReply(t, nil) })
	t.Run("first reply fails", func(t *testing.T) {
		testTrojanUDPSlowReply(t, errors.New("first reply write failed"))
	})
}

func testTrojanUDPSlowReply(t *testing.T, writeErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = policy.ContextWithBufferPolicy(ctx, policy.Buffer{PerConnection: 128})

	first := trojanUDPTestPacket{net.UDPDestination(net.LocalHostIP, 10001), "blocked client"}
	slowRepliesSent := make(chan struct{}, 3)
	carrierClient, carrierServer := trojanTestTCPPair(t, ctx)
	server := multiplex.NewServerWorker(ctx, func(ctx context.Context, dest net.Destination, link *transport.Link) error {
		defer common.Close(link.Writer)
		for {
			packets, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(packets)
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			count := len(packets)
			if err := link.Writer.WriteMultiBuffer(packets); err != nil {
				return err
			}
			if dest == first.dest {
				for range count {
					select {
					case slowRepliesSent <- struct{}{}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
		}
	}, &transport.Link{Reader: buf.NewReader(carrierServer), Writer: buf.NewWriter(carrierServer)})
	defer server.Close()
	worker := multiplex.NewClientWorker(ctx, transport.Link{
		Reader: buf.NewReader(carrierClient), Writer: buf.NewWriter(carrierClient),
	}, multiplex.ClientStrategy{})
	defer worker.Close()

	dispatcher := &trojanTestDispatcher{dispatchLink: func(routeCtx context.Context, dest net.Destination, link *transport.Link) error {
		routeCtx = session.ContextWithOutbounds(routeCtx, []*session.Outbound{{Target: dest}})
		return multiplex.Dispatch(routeCtx, link, func(ctx context.Context, s *multiplex.Session) error {
			if !worker.TryAdmit(ctx, s) {
				return errors.New("could not admit mux child")
			}
			return nil
		})
	}}
	slow, slowConn := trojanTestTCPPair(t, ctx)
	writing, release := make(chan struct{}), make(chan struct{})
	var firstWrite sync.Once
	slowHeader, slowDone := serveTrojanTest(t, ctx, trojanTestConn{
		Conn: slowConn, write: func(data []byte) (int, error) {
			firstWrite.Do(func() { close(writing) })
			select {
			case <-release:
				if writeErr != nil {
					return 0, writeErr
				}
				return slowConn.Write(data)
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		},
	}, dispatcher)
	if err := writeTrojanUDPTestRequest(slow, slowHeader, first); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writing:
	case <-ctx.Done():
		t.Fatal("slow carrier never started writing its response")
	}

	waitForSlowReply := func() {
		t.Helper()
		select {
		case <-slowRepliesSent:
		case <-ctx.Done():
			t.Fatal("mux server did not write the slow client's response")
		}
	}
	waitForSlowReply()
	var pending []trojanUDPTestPacket
	if writeErr == nil {
		pending = []trojanUDPTestPacket{{first.dest, "queued second reply"}, {first.dest, "queued third reply"}}
		writer := &PacketWriter{Writer: slow}
		for _, packet := range pending {
			if err := writeTrojanUDPTestPacket(writer, packet); err != nil {
				t.Fatal(err)
			}
			waitForSlowReply()
		}
	}

	fast, fastHeader, _ := openTrojanTestClient(t, ctx, dispatcher)
	second := trojanUDPTestPacket{net.UDPDestination(net.LocalHostIP, 10002), "sibling client"}
	if err := writeTrojanUDPTestRequest(fast, fastHeader, second); err != nil {
		t.Fatal(err)
	}
	if err := readTrojanUDPTestPacket(&PacketReader{Reader: fast}, second); err != nil {
		t.Fatalf("sibling reply while the first write was blocked: %v", err)
	}
	if worker.TotalConnections() != 2 {
		t.Fatal("both requests must use the same mux worker")
	}
	close(release)
	if writeErr == nil {
		reader := &PacketReader{Reader: slow}
		for _, packet := range append([]trojanUDPTestPacket{first}, pending...) {
			if err := readTrojanUDPTestPacket(reader, packet); err != nil {
				t.Fatalf("slow reply after releasing its write: %v", err)
			}
		}
		return
	}

	select {
	case err := <-slowDone:
		if !errors.Is(err, writeErr) {
			t.Fatalf("slow carrier returned %v, want %v", err, writeErr)
		}
	case <-ctx.Done():
		t.Fatal("slow carrier stayed open after failed write")
	}

	second.data = "sibling after failed write"
	if err := writeTrojanUDPTestPacket(&PacketWriter{Writer: fast}, second); err != nil {
		t.Fatal(err)
	}
	if err := readTrojanUDPTestPacket(&PacketReader{Reader: fast}, second); err != nil {
		t.Fatalf("sibling reply after the other carrier failed: %v", err)
	}
	if worker.TotalConnections() != 2 {
		t.Fatal("the existing sibling stream should survive the failed reply")
	}
}

func TestTrojanUDPCloseWriteEndsRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	packet := trojanUDPTestPacket{net.UDPDestination(net.LocalHostIP, 10001), "before EOF"}
	dispatched := make(chan error, 1)
	requestRead := make(chan struct{})
	dispatcher := &trojanTestDispatcher{dispatchLink: func(routeCtx context.Context, _ net.Destination, link *transport.Link) (err error) {
		defer func() { dispatched <- err }()
		if err := readTrojanUDPTestPacket(link.Reader, packet); err != nil {
			return err
		}
		close(requestRead)
		<-routeCtx.Done()
		if err := writeTrojanUDPTestPacket(link.Writer, packet); !errors.Is(err, io.ErrClosedPipe) {
			return fmt.Errorf("reply after carrier EOF: got %v, want closed pipe", err)
		}
		return nil
	}}
	client, header, processDone := openTrojanTestClient(t, ctx, dispatcher)
	if err := writeTrojanUDPTestRequest(client, header, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requestRead:
	case <-ctx.Done():
		t.Fatal("outbound did not read the first packet")
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dispatched:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("peer EOF did not cancel the outbound")
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Trojan Process returned %v after peer EOF", err)
		}
	case <-ctx.Done():
		t.Fatal("Trojan Process stayed blocked after peer EOF")
	}
	mb, err := (&PacketReader{Reader: client}).ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if len(mb) != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after CloseWrite returned %d buffers and %v", len(mb), err)
	}
}
