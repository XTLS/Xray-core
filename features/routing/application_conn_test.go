package routing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type applicationTestDispatcher struct {
	Dispatcher
	dispatch func(context.Context, net.Destination, *transport.Link) error
}

func (d applicationTestDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	return d.dispatch(ctx, dest, link)
}

type applicationTestCounter struct{ value atomic.Int64 }

func (c *applicationTestCounter) Value() int64      { return c.value.Load() }
func (c *applicationTestCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *applicationTestCounter) Add(v int64) int64 { return c.value.Add(v) }

func TestApplicationDialAdmissionAndServerFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx = policy.ContextWithBufferPolicy(ctx, policy.Buffer{PerConnection: 3})
	target := net.TCPDestination(net.LocalHostIP, 12345)
	ready := make(chan struct{})
	attempted, consumed := new(applicationTestCounter), new(applicationTestCounter)
	dispatcher := applicationTestDispatcher{dispatch: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
		if dest != target {
			return fmt.Errorf("route destination = %v, want %v", dest, target)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		}
		binder := link.Reader.(interface{ SetUplinkCounter(stats.Counter) })
		binder.SetUplinkCounter(attempted)
		binder.SetUplinkCounter(consumed)
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("greeting"))); err != nil {
			return err
		}
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		defer buf.ReleaseMulti(mb)
		var offer [6]byte
		if mb.Len() != int32(len(offer)) || mb.Copy(offer[:]) != len(offer) || string(offer[:]) != "onetwo" {
			return fmt.Errorf("accepted writes out of order: %q", offer[:])
		}
		return link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("final")))
	}}
	conn, err := DialApplication(ctx, dispatcher, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	first := []byte("one")
	if n, err := conn.Write(first); n != len(first) || err != nil {
		t.Fatalf("first write = %d, %v", n, err)
	}
	clear(first)
	if _, err := io.WriteString(conn, "two"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := io.WriteString(conn, "x"); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write above admission budget = %d, %v", n, err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(ready)
	received, err := io.ReadAll(conn)
	if err != nil || string(received) != "greetingfinal" {
		t.Fatalf("received %q, %v", received, err)
	}
	if attempted.Value() != 7 || consumed.Value() != 6 {
		t.Fatalf("counters = %d attempted, %d consumed", attempted.Value(), consumed.Value())
	}
	if conn.RemoteAddr().String() != "0.0.0.0:0" || conn.LocalAddr().String() != "0.0.0.0:0" {
		t.Fatal("application connection exposed the routed endpoint address")
	}
}

func TestApplicationDialCloseWakesOperations(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	parent, cancel := context.WithCancel(policy.ContextWithBufferPolicy(ctx, policy.Buffer{PerConnection: 0}))
	defer cancel()
	started, ended := make(chan context.Context, 1), make(chan error, 1)
	dispatcher := applicationTestDispatcher{dispatch: func(route context.Context, _ net.Destination, link *transport.Link) error {
		started <- route
		<-route.Done()
		mb, err := link.Reader.ReadMultiBuffer()
		if len(mb) != 0 {
			buf.ReleaseMulti(mb)
			err = errors.New("canceled route read admitted bytes")
		}
		ended <- err
		return err
	}}
	conn, err := DialApplication(parent, dispatcher, net.TCPDestination(net.LocalHostIP, 12345))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var route context.Context
	select {
	case route = <-started:
	case <-ctx.Done():
		t.Fatal("route did not start")
	}
	if _, err := io.WriteString(conn, "claim"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() {
		var b [1]byte
		_, err := conn.Read(b[:])
		done <- err
	}()
	go func() {
		_, err := io.WriteString(conn, "blocked")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("blocked operation returned early: %v", err)
	case <-time.After(15 * time.Millisecond):
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("operation after close: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("close did not wake I/O")
		}
	}
	if route.Err() != nil {
		t.Fatal("close canceled a route with admitted writes")
	}
	cancel()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("route input after parent cancellation = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("parent cancellation did not abort the closed route")
	}
}

func TestApplicationDialCloseDrainsAdmittedWrites(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	take, finish := make(chan struct{}), make(chan struct{})
	taken, ended := make(chan error, 1), make(chan error, 1)
	started := make(chan context.Context, 1)
	dispatcher := applicationTestDispatcher{dispatch: func(route context.Context, _ net.Destination, link *transport.Link) error {
		started <- route
		select {
		case <-take:
		case <-route.Done():
			taken <- route.Err()
			return route.Err()
		}
		mb, err := link.Reader.ReadMultiBuffer()
		var received [7]byte
		if err == nil && (mb.Len() != int32(len(received)) || mb.Copy(received[:]) != len(received) || string(received[:]) != "request") {
			err = fmt.Errorf("admitted request = %q", received[:])
		}
		buf.ReleaseMulti(mb)
		taken <- err
		if err != nil {
			return err
		}
		select {
		case <-finish:
		case <-route.Done():
			ended <- route.Err()
			return route.Err()
		}
		mb, err = link.Reader.ReadMultiBuffer()
		if len(mb) != 0 || !errors.Is(err, io.EOF) {
			buf.ReleaseMulti(mb)
			err = fmt.Errorf("sealed route input = %d buffers, %v", len(mb), err)
		} else {
			err = nil
		}
		ended <- err
		return err
	}}
	conn, err := DialApplication(ctx, dispatcher, net.TCPDestination(net.LocalHostIP, 12345))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var route context.Context
	select {
	case route = <-started:
	case <-ctx.Done():
		t.Fatal("route did not start")
	}
	if _, err := io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if route.Err() != nil {
		t.Fatal("close canceled the route before it took admitted writes")
	}
	close(take)
	select {
	case err := <-taken:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("admitted write did not drain")
	}
	if route.Err() != nil {
		t.Fatal("close canceled the route while it owned admitted data")
	}
	close(finish)
	select {
	case err := <-ended:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("sealed uplink did not deliver EOF")
	}
}

func TestApplicationDialEmptyCloseCancelsRoute(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	started, ended := make(chan struct{}), make(chan struct{})
	dispatcher := applicationTestDispatcher{dispatch: func(ctx context.Context, _ net.Destination, _ *transport.Link) error {
		close(started)
		<-ctx.Done()
		close(ended)
		return ctx.Err()
	}}
	conn, err := DialApplication(ctx, dispatcher, net.TCPDestination(net.LocalHostIP, 12345))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("route did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
		if ctx.Err() != nil {
			t.Fatal("empty close required the parent deadline to cancel the route")
		}
	case <-ctx.Done():
		t.Fatal("empty close did not cancel the selected route")
	}
}

func TestApplicationDialKeepsPacketBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx = policy.ContextWithBufferPolicy(ctx, policy.Buffer{PerConnection: 1024})
	writesReady := make(chan struct{})
	target := net.UDPDestination(net.LocalHostIP, 12345)
	dispatcher := applicationTestDispatcher{dispatch: func(ctx context.Context, dest net.Destination, link *transport.Link) error {
		select {
		case <-writesReady:
		case <-ctx.Done():
			return ctx.Err()
		}
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		if dest != target || len(mb) != 2 || string(mb[0].Bytes()) != "abc" || string(mb[1].Bytes()) != "defghi" {
			buf.ReleaseMulti(mb)
			return errors.New("fixed-peer writes lost their packet boundaries")
		}
		return link.Writer.WriteMultiBuffer(mb)
	}}
	conn, err := DialApplication(ctx, dispatcher, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, packet := range []string{"abc", "defghi"} {
		if _, err := io.WriteString(conn, packet); err != nil {
			t.Fatal(err)
		}
	}
	close(writesReady)
	for _, expected := range []string{"ab", "de"} {
		var b [2]byte
		n, err := conn.Read(b[:])
		if string(b[:n]) != expected || err != nil {
			t.Fatalf("truncated packet = %q, %v, want %q", b[:n], err, expected)
		}
	}
	var b [2]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("packet reader after two records = %d, %v", n, err)
	}
}

func TestApplicationDialTimedRouteReadRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	sniffed := make(chan struct{})
	dispatcher := applicationTestDispatcher{dispatch: func(_ context.Context, _ net.Destination, link *transport.Link) error {
		timed := link.Reader.(buf.TimeoutReader)
		mb, err := timed.ReadMultiBufferTimeout(10 * time.Millisecond)
		if !errors.Is(err, buf.ErrReadTimeout) {
			buf.ReleaseMulti(mb)
			return fmt.Errorf("timed route read: %v", err)
		}
		close(sniffed)
		mb, err = link.Reader.ReadMultiBuffer()
		if err != nil {
			return err
		}
		return link.Writer.WriteMultiBuffer(mb)
	}}
	conn, err := DialApplication(ctx, dispatcher, net.TCPDestination(net.LocalHostIP, 12345))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-sniffed:
	case <-ctx.Done():
		t.Fatal("route did not complete its timed read")
	}
	var b [3]byte
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("application read deadline = %d, %v", n, err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "yes"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, b[:]); err != nil || string(b[:]) != "yes" {
		t.Fatalf("read after deadline and sniff reset = %q, %v", b[:], err)
	}
}
