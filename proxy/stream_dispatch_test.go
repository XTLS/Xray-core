package proxy

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type streamTestDispatcher struct {
	routing.Dispatcher
	run func(*transport.Link) error
}

func (d streamTestDispatcher) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	return d.run(link)
}

type testFrameReader struct {
	conn stdnet.Conn
}

func (r testFrameReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	if _, err := io.ReadFull(r.conn, b.Extend(4)); err != nil {
		b.Release()
		return nil, err
	}
	return buf.MultiBuffer{b}, nil
}

func TestDispatchInboundStreamPreservesPartialSniffAndPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	in, peer := stdnet.Pipe()
	defer in.Close()
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	finishFrame := make(chan struct{})
	written := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(peer, "ab"); err != nil {
			written <- err
			return
		}
		select {
		case <-finishFrame:
			_, err := io.WriteString(peer, "cd")
			written <- err
		case <-ctx.Done():
			written <- ctx.Err()
		}
	}()
	check := func(mb buf.MultiBuffer, err error, want string) error {
		defer buf.ReleaseMulti(mb)
		if err != nil {
			return err
		}
		got := make([]byte, mb.Len())
		mb.Copy(got)
		if string(got) != want {
			t.Errorf("read %q, want %q", got, want)
		}
		return nil
	}
	d := streamTestDispatcher{run: func(link *transport.Link) error {
		reader := link.Reader.(buf.TimeoutReader)
		mb, err := reader.ReadMultiBufferTimeout(time.Second)
		if err := check(mb, err, "prefix"); err != nil {
			return err
		}
		mb, err = reader.ReadMultiBufferTimeout(time.Millisecond)
		buf.ReleaseMulti(mb)
		if !errors.Is(err, buf.ErrReadTimeout) {
			return errors.New("expected timeout with an incomplete frame")
		}
		close(finishFrame)
		mb, err = link.Reader.ReadMultiBuffer()
		return check(mb, err, "abcd")
	}}
	dest := net.TCPDestination(net.LocalHostIP, 1234)
	p := policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Second}}
	first := buf.MergeBytes(nil, []byte("prefix"))
	if err := DispatchInboundStream(ctx, in, p, d, dest, testFrameReader{in}, buf.NewWriter(in), first); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestDispatchInboundStreamReceivesDuringOpening(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	carrier, peer := stdnet.Pipe()
	defer carrier.Close()
	defer peer.Close()
	peer.SetWriteDeadline(time.Now().Add(time.Second))

	opening := make(chan struct{})
	resolved := make(chan struct{})
	consumed := make(chan struct{})
	counter := new(stats.Counter)
	nested := new(stats.Counter)
	d := streamTestDispatcher{run: func(link *transport.Link) error {
		close(opening)
		select {
		case <-resolved:
		case <-ctx.Done():
			return ctx.Err()
		}
		reader := link.Reader.(*inboundStreamReader)
		reader.SetUplinkCounter(counter)
		reader.SetUplinkCounter(nested)
		if nested.Value() != 0 {
			return errors.New("read accounting advanced before consumption")
		}
		input := &buf.BufferedReader{Reader: reader}
		defer func() { buf.ReleaseMulti(input.Buffer) }()
		got := make([]byte, 12)
		if _, err := io.ReadFull(input, got); err != nil {
			return err
		}
		if string(got) != "headabcdefgh" || counter.Value() != 12 || nested.Value() != 12 {
			t.Errorf("staged input = %q, attempted = %d, consumed = %d", got, counter.Value(), nested.Value())
		}
		close(consumed)
		got = got[:8]
		if _, err := io.ReadFull(input, got); err != nil {
			return err
		}
		if string(got) != "ijklmnop" || counter.Value() != 20 || nested.Value() != 20 {
			t.Errorf("continued input = %q, attempted = %d, consumed = %d", got, counter.Value(), nested.Value())
		}
		return nil
	}}
	p := policy.Session{
		Timeouts: policy.Timeout{ConnectionIdle: time.Second},
		Buffer:   policy.Buffer{PerConnection: 11},
	}
	done := make(chan error, 1)
	go func() {
		first := buf.MergeBytes(nil, []byte("head"))
		done <- DispatchInboundStream(ctx, carrier, p, d, net.TCPDestination(net.LocalHostIP, 1234), testFrameReader{carrier}, buf.NewWriter(carrier), first)
	}()

	select {
	case <-opening:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// These writes complete while the route has yet to call the reader.
	if _, err := io.WriteString(peer, "abcdefgh"); err != nil {
		t.Fatalf("client could not send during outbound opening: %v", err)
	}
	close(resolved)
	select {
	case <-consumed:
	case err := <-done:
		t.Fatalf("route ended before reading staged bytes: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := io.WriteString(peer, "ijklmnop"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestDispatchInboundStreamReceivesDuringEstablishedWriteStall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	carrier, peer := stdnet.Pipe()
	defer carrier.Close()
	defer peer.Close()
	peer.SetWriteDeadline(time.Now().Add(time.Second))

	established := make(chan struct{})
	resume := make(chan struct{})
	d := streamTestDispatcher{run: func(link *transport.Link) error {
		input := &buf.BufferedReader{Reader: link.Reader}
		defer func() { buf.ReleaseMulti(input.Buffer) }()
		var first [4]byte
		if _, err := io.ReadFull(input, first[:]); err != nil {
			return err
		}
		if string(first[:]) != "head" {
			t.Errorf("first bytes = %q, want head", first)
		}
		close(established)
		// The outbound's request copy is holding the first batch in a
		// physical write. It cannot call for a second batch yet.
		select {
		case <-resume:
		case <-ctx.Done():
			return ctx.Err()
		}
		var rest [12]byte
		if _, err := io.ReadFull(input, rest[:]); err != nil {
			return err
		}
		if string(rest[:]) != "abcdefghijkl" {
			t.Errorf("staged bytes = %q, want abcdefghijkl", rest)
		}
		return nil
	}}
	p := policy.Session{
		Timeouts: policy.Timeout{ConnectionIdle: time.Second},
		Buffer:   policy.Buffer{PerConnection: 4},
	}
	done := make(chan error, 1)
	go func() {
		done <- DispatchInboundStream(ctx, carrier, p, d, net.TCPDestination(net.LocalHostIP, 1234), testFrameReader{carrier}, buf.NewWriter(carrier), nil)
	}()
	if _, err := io.WriteString(peer, "head"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-established:
	case err := <-done:
		t.Fatalf("route ended before its first read: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Two batches can queue under the soft limit. The decoder owns one
	// additional batch while waiting for room, as in the legacy producer.
	if _, err := io.WriteString(peer, "abcdefghijkl"); err != nil {
		t.Fatalf("client could not send while the established route was writing: %v", err)
	}
	if err := peer.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := io.WriteString(peer, "mnop"); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("input beyond the receive budget = %d bytes, %v", n, err)
	}
	close(resume)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type gatedStreamWriter struct {
	entered   chan struct{}
	gate      chan struct{}
	carrier   <-chan struct{}
	once      sync.Once
	writeErr  error
	data      []byte
	closeCall int
}

func (w *gatedStreamWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.once.Do(func() { close(w.entered) })
	select {
	case <-w.carrier:
		return io.ErrClosedPipe
	case <-w.gate:
		if w.writeErr != nil {
			return w.writeErr
		}
		for _, b := range mb {
			w.data = append(w.data, b.Bytes()...)
		}
		return nil
	}
}

func (w *gatedStreamWriter) Close() error {
	w.closeCall++
	return nil
}

type testStreamCarrier struct {
	stdnet.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *testStreamCarrier) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestDispatchInboundStreamResponseSender(t *testing.T) {
	errWrite := errors.New("carrier write failed")
	for _, tc := range []struct {
		name     string
		abort    bool
		writeErr error
	}{
		{name: "graceful drain"},
		{name: "abort", abort: true},
		{name: "carrier write failure", writeErr: errWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, peer := stdnet.Pipe()
			defer peer.Close()
			carrier := &testStreamCarrier{Conn: raw, closed: make(chan struct{})}
			writer := &gatedStreamWriter{
				entered: make(chan struct{}), gate: make(chan struct{}), carrier: carrier.closed, writeErr: tc.writeErr,
			}
			accepted := make(chan *transport.Link, 1)
			put := make([]*buf.Buffer, 4)
			for i, s := range []string{"a", "b", "c", "d"} {
				put[i] = buf.New()
				put[i].WriteString(s)
			}
			d := streamTestDispatcher{run: func(link *transport.Link) error {
				if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{put[0]}); err != nil {
					return err
				}
				select {
				case <-writer.entered:
				case <-ctx.Done():
					return ctx.Err()
				}
				for _, b := range put[1:3] {
					if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
						return err
					}
				}
				if tc.abort {
					accepted <- link
					err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{put[3]})
					if !errors.Is(err, io.ErrClosedPipe) {
						return errors.New("expected the full-queue producer to be rejected on abort")
					}
					return nil
				}
				put[3].Release()
				if err := common.Close(link.Writer); err != nil {
					return err
				}
				common.Interrupt(link.Reader)
				accepted <- link
				return nil
			}}
			p := policy.Session{
				Timeouts: policy.Timeout{ConnectionIdle: 2 * time.Second},
				Buffer:   policy.Buffer{PerConnection: 1},
			}
			result := make(chan error, 1)
			go func() {
				result <- DispatchInboundStream(ctx, carrier, p, d, net.TCPDestination(net.LocalHostIP, 1234), buf.NewReader(carrier), writer, nil)
			}()
			var link *transport.Link
			select {
			case link = <-accepted:
			case err := <-result:
				t.Fatalf("route ended before bounded response admission: %v", err)
			case <-ctx.Done():
				t.Fatal("queued response waited for the carrier write")
			}
			select {
			case <-carrier.closed:
				t.Fatal("carrier closed before the admitted response was drained or aborted")
			default:
			}
			if tc.abort {
				common.Interrupt(link.Writer)
			} else {
				close(writer.gate)
			}
			select {
			case err := <-result:
				if !errors.Is(err, tc.writeErr) {
					t.Fatalf("route error = %v, want %v", err, tc.writeErr)
				}
			case <-ctx.Done():
				t.Fatal("response sender or waiting producer did not stop")
			}

			want, wantClose := "abc", 1
			if tc.abort || tc.writeErr != nil {
				want, wantClose = "", 0
			}
			if string(writer.data) != want || writer.closeCall != wantClose {
				t.Fatalf("carrier got %q and %d graceful closes, want %q and %d", writer.data, writer.closeCall, want, wantClose)
			}
			for i, b := range put {
				if !b.IsEmpty() {
					t.Fatalf("response record %d was not released", i)
				}
			}
			select {
			case <-carrier.closed:
			default:
				t.Fatal("route returned with its carrier still open")
			}
		})
	}
}
