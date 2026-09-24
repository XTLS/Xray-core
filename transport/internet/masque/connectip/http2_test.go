package connectip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type pipeResponseWriter struct {
	*io.PipeWriter
	header     http.Header
	status     int
	headerOnce sync.Once
	headerDone chan struct{}
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(code int) {
	w.headerOnce.Do(func() {
		w.status = code
		close(w.headerDone)
	})
}

func (w *pipeResponseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.PipeWriter.Write(b)
}

func (w *pipeResponseWriter) Flush() {}

func http2RoundTripper(handler http.HandlerFunc) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		w := &pipeResponseWriter{PipeWriter: pw, header: http.Header{}, headerDone: make(chan struct{})}
		sr := r.Clone(r.Context())
		sr.Proto, sr.ProtoMajor, sr.ProtoMinor = "HTTP/2.0", 2, 0
		go func() {
			handler(w, sr)
			w.WriteHeader(http.StatusOK)
			pw.Close()
		}()
		<-w.headerDone
		return &http.Response{StatusCode: w.status, Header: w.header, Body: pr}, nil
	})
}

func setupHTTP2Conns(t *testing.T) (client, server *Conn) {
	t.Helper()

	serverConns := make(chan *Conn, 1)
	rt := http2RoundTripper(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		req, err := ParseProxyRequest(r)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, err := (&Proxy{}).Proxy(w, req)
		if !assert.NoError(t, err) {
			return
		}
		serverConns <- conn
		<-conn.closeChan
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := NewRequest(ctx, "https://example.org/connect-ip")
	require.NoError(t, err)
	req.Header().Set("Authorization", "Bearer token")
	client, rsp, err := NewHTTP2ClientConn(rt).Dial(req)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	require.Equal(t, "?1", rsp.Header.Get("Capsule-Protocol"))

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	case server = <-serverConns:
	}
	t.Cleanup(func() { server.Close() })
	return client, server
}

func newTestHTTP2Stream() (*http2Stream, *io.PipeWriter) {
	pr, pw := io.Pipe()
	return &http2Stream{reader: bufio.NewReader(pr), body: newRequestBody(), rsp: pr, cancel: func() {}}, pw
}

func TestHTTP2Request(t *testing.T) {
	requests := make(chan *http.Request, 1)
	pr, pw := io.Pipe()
	defer pw.Close()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests <- r
		return &http.Response{StatusCode: http.StatusOK, Body: pr}, nil
	})
	req, err := NewRequest(t.Context(), "https://proxy.example:8443/.well-known/masque/ip/*/*/")
	require.NoError(t, err)
	req.Header().Set("Authorization", "Bearer token")
	conn, _, err := NewHTTP2ClientConn(rt).Dial(req)
	require.NoError(t, err)
	defer conn.Close()

	r := <-requests
	require.Equal(t, http.MethodConnect, r.Method)
	require.Equal(t, []string{requestProtocol}, r.Header[":protocol"])
	require.Equal(t, "?1", r.Header.Get("Capsule-Protocol"))
	require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
	require.Equal(t, "proxy.example:8443", r.Host)
	require.Equal(t, "https", r.URL.Scheme)
	require.Equal(t, "/.well-known/masque/ip/*/*/", r.URL.Path)
	require.NotNil(t, r.Body)
	require.Empty(t, req.Header().Values(":protocol"))
	require.Equal(t, maxCapsulePacketSize, conn.MaxPacketSize())
}

func TestHTTP2DialErrors(t *testing.T) {
	newReq := func(ctx context.Context) *Request {
		req, err := NewRequest(ctx, "https://example.org/connect-ip")
		require.NoError(t, err)
		return req
	}

	t.Run("status", func(t *testing.T) {
		var streamCtx context.Context
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			streamCtx = r.Context()
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		})
		_, rsp, err := NewHTTP2ClientConn(rt).Dial(newReq(t.Context()))
		require.EqualError(t, err, "connect-ip: server responded with 403")
		require.Equal(t, http.StatusForbidden, rsp.StatusCode)
		require.ErrorIs(t, streamCtx.Err(), context.Canceled)
	})

	t.Run("round trip", func(t *testing.T) {
		errRoundTrip := errors.New("extended connect not supported by peer")
		rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errRoundTrip })
		_, _, err := NewHTTP2ClientConn(rt).Dial(newReq(t.Context()))
		require.ErrorIs(t, err, errRoundTrip)
	})

	t.Run("context", func(t *testing.T) {
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, _, err := NewHTTP2ClientConn(rt).Dial(newReq(ctx))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestHTTP2Packets(t *testing.T) {
	client, server := setupHTTP2Conns(t)
	clientV4 := netip.MustParseAddr("192.0.2.2")
	clientV6 := netip.MustParseAddr("2001:db8::2")
	require.NoError(t, server.AssignAddresses([]netip.Prefix{netip.PrefixFrom(clientV4, 32), netip.PrefixFrom(clientV6, 128)}))
	require.NoError(t, server.AdvertiseRoute([]IPRoute{
		{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")},
		{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	_, err = client.Routes(ctx)
	require.NoError(t, err)
	require.Equal(t, maxCapsulePacketSize, client.MaxPacketSize())

	for _, tc := range []struct {
		name   string
		up     []byte
		down   []byte
		ttlOff int
	}{
		{
			name:   "IPv4",
			up:     ipv4Packet(64, 17, clientV4, testDst4, nil, []byte("foobar")),
			down:   ipv4Packet(64, 17, testDst4, clientV4, nil, []byte("barfoo")),
			ttlOff: 8,
		},
		{
			name:   "IPv6 larger than a QUIC datagram",
			up:     ipv6Packet(64, 17, clientV6, testDst6, bytes.Repeat([]byte("up"), 4500)),
			down:   ipv6Packet(64, 17, testDst6, clientV6, bytes.Repeat([]byte("down"), 2250)),
			ttlOff: 7,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, dir := range []struct {
				from, to *Conn
				packet   []byte
			}{
				{client, server, tc.up},
				{server, client, tc.down},
			} {
				icmp, err := dir.from.WritePacket(slices.Clone(dir.packet))
				require.NoError(t, err)
				require.Nil(t, icmp)
				b := make([]byte, 1<<16)
				n, err := dir.to.ReadPacket(b)
				require.NoError(t, err)
				require.Len(t, b[:n], len(dir.packet))
				require.Equal(t, dir.packet[tc.ttlOff]-1, b[tc.ttlOff])
				if tc.ttlOff == 8 {
					require.True(t, ipv4ChecksumValid(b[:ipv4.HeaderLen]))
					require.Equal(t, dir.packet[ipv4.HeaderLen:], b[ipv4.HeaderLen:n])
				} else {
					require.Equal(t, dir.packet[ipv6.HeaderLen:], b[ipv6.HeaderLen:n])
				}
			}
		})
	}

	t.Run("in order both ways at once", func(t *testing.T) {
		const count = 2000
		var wg sync.WaitGroup
		for _, dir := range []struct {
			from, to *Conn
			src, dst netip.Addr
		}{
			{client, server, clientV4, testDst4},
			{server, client, testDst4, clientV4},
		} {
			wg.Go(func() {
				for i := range count {
					payload := make([]byte, 1200)
					payload[0], payload[1] = byte(i>>8), byte(i)
					if _, err := dir.from.WritePacket(ipv4Packet(64, 17, dir.src, dir.dst, nil, payload)); !assert.NoError(t, err) {
						return
					}
				}
			})
			wg.Go(func() {
				b := make([]byte, 1500)
				for i := range count {
					n, err := dir.to.ReadPacket(b)
					if !assert.NoError(t, err) || !assert.Equal(t, ipv4.HeaderLen+1200, n) {
						return
					}
					if !assert.Equal(t, i, int(b[ipv4.HeaderLen])<<8|int(b[ipv4.HeaderLen+1])) {
						return
					}
				}
			})
		}
		wg.Wait()
	})
}

func TestHTTP2AddressRequest(t *testing.T) {
	client, server := setupHTTP2Conns(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := client.RequestAddresses([]netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 32),
		netip.PrefixFrom(netip.IPv6Unspecified(), 128),
	})
	require.NoError(t, err)
	req, err := server.ReceiveAddressRequest(ctx)
	require.NoError(t, err)
	require.Len(t, req.Prefixes, 2)
	require.NoError(t, req.Respond([]netip.Prefix{netip.MustParsePrefix("192.0.2.2/32"), {}}, nil))

	assigned, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Len(t, assigned, 2)
	require.Equal(t, netip.MustParsePrefix("192.0.2.2/32"), assigned[0].IPPrefix)
	require.True(t, assigned[1].Rejected())
}

func TestHTTP2Closing(t *testing.T) {
	for _, side := range []string{"client", "proxy"} {
		t.Run(side, func(t *testing.T) {
			client, server := setupHTTP2Conns(t)
			closing, peer := client, server
			if side == "proxy" {
				closing, peer = server, client
			}

			require.NoError(t, closing.Close())
			_, err := closing.ReadPacket(make([]byte, 1500))
			require.ErrorIs(t, err, net.ErrClosed)
			_, err = closing.WritePacket(ipv4Packet(64, 17, testSrc4, testDst4, nil, nil))
			require.ErrorIs(t, err, net.ErrClosed)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err = peer.Routes(ctx)
			require.ErrorIs(t, err, net.ErrClosed)
			var closeErr *CloseError
			require.ErrorAs(t, err, &closeErr)
			require.True(t, closeErr.Remote)
			_, err = peer.ReadPacket(make([]byte, 1500))
			require.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func TestHTTP2CloseUnblocksWrites(t *testing.T) {
	str, pw := newTestHTTP2Stream()
	defer pw.Close()
	conn := newProxiedConn(str)

	writeErr := make(chan error, 1)
	go func() {
		for {
			if _, err := conn.WritePacket(ipv4Packet(64, 17, testSrc4, testDst4, nil, make([]byte, 1000))); err != nil {
				writeErr <- err
				return
			}
		}
	}()
	require.Eventually(t, func() bool {
		str.body.mu.Lock()
		defer str.body.mu.Unlock()
		return len(str.body.buf) >= maxBufferedRequestBody
	}, 5*time.Second, time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on a stalled stream")
	}
	require.ErrorIs(t, <-writeErr, net.ErrClosed)
}

func TestHTTP2DatagramCapsules(t *testing.T) {
	str, pw := newTestHTTP2Stream()
	defer pw.Close()
	conn := newProxiedConn(str)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255")},
	}))

	capsule := func(payload []byte) []byte {
		b := quicvarint.Append(nil, uint64(capsuleTypeDatagram))
		b = quicvarint.Append(b, uint64(len(payload)))
		return append(b, payload...)
	}
	packet := ipv4Packet(64, 17, testSrc4, testDst4, nil, []byte("foobar"))
	go func() {
		for _, c := range [][]byte{
			capsule(nil),
			capsule([]byte{0x40}),
			capsule(append([]byte{0x02}, packet...)),
			capsule(append(bytes.Clone(contextIDZero), make([]byte, maxCapsulePacketSize+1)...)),
			capsule(append(bytes.Clone(contextIDZero), packet...)),
		} {
			if _, err := pw.Write(c); err != nil {
				return
			}
		}
	}()
	b := make([]byte, 1500)
	n, err := conn.ReadPacket(b)
	require.NoError(t, err)
	require.Equal(t, packet, b[:n])
}

func TestHTTP2WritesDatagramCapsules(t *testing.T) {
	str, pw := newTestHTTP2Stream()
	defer pw.Close()
	conn := newProxiedConn(str)
	t.Cleanup(func() { conn.Close() })

	packet := ipv4Packet(64, 17, testSrc4, testDst4, nil, []byte("foobar"))
	_, err := conn.WritePacket(slices.Clone(packet))
	require.NoError(t, err)

	p := http3.NewCapsuleParser(str.body)
	typ, cr, err := p.Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeDatagram, typ)
	data, err := io.ReadAll(cr)
	require.NoError(t, err)
	require.Equal(t, contextIDZero, data[:len(contextIDZero)])
	sent := data[len(contextIDZero):]
	require.Len(t, sent, len(packet))
	require.Equal(t, packet[8]-1, sent[8])
	require.Equal(t, packet[ipv4.HeaderLen:], sent[ipv4.HeaderLen:])
}

func TestRequestBody(t *testing.T) {
	t.Run("coalesces writes", func(t *testing.T) {
		b := newRequestBody()
		for _, s := range []string{"foo", "bar", "baz"} {
			_, err := b.Write([]byte(s))
			require.NoError(t, err)
		}
		p := make([]byte, 16)
		n, err := b.Read(p)
		require.NoError(t, err)
		require.Equal(t, "foobarbaz", string(p[:n]))
	})

	t.Run("blocks writes while full", func(t *testing.T) {
		b := newRequestBody()
		_, err := b.Write(make([]byte, maxBufferedRequestBody))
		require.NoError(t, err)
		written := make(chan struct{})
		go func() {
			b.Write([]byte("x"))
			close(written)
		}()
		select {
		case <-written:
			t.Fatal("write did not block")
		case <-time.After(50 * time.Millisecond):
		}
		_, err = b.Read(make([]byte, maxBufferedRequestBody))
		require.NoError(t, err)
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Fatal("write stayed blocked")
		}
	})

	t.Run("close", func(t *testing.T) {
		b := newRequestBody()
		_, err := b.Write([]byte("foo"))
		require.NoError(t, err)
		require.NoError(t, b.Close())
		_, err = b.Write([]byte("bar"))
		require.ErrorIs(t, err, io.ErrClosedPipe)
		data, err := io.ReadAll(b)
		require.NoError(t, err)
		require.Equal(t, "foo", string(data))
	})

	t.Run("write deadline", func(t *testing.T) {
		b := newRequestBody()
		_, err := b.Write(make([]byte, maxBufferedRequestBody))
		require.NoError(t, err)
		writeErr := make(chan error, 1)
		go func() {
			_, err := b.Write([]byte("x"))
			writeErr <- err
		}()
		require.NoError(t, b.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
		select {
		case err := <-writeErr:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		case <-time.After(time.Second):
			t.Fatal("write deadline did not unblock the write")
		}
		require.NoError(t, b.Close())
		data, err := io.ReadAll(b)
		require.NoError(t, err)
		require.Len(t, data, maxBufferedRequestBody)
	})

	t.Run("close with error", func(t *testing.T) {
		b := newRequestBody()
		_, err := b.Write([]byte("foo"))
		require.NoError(t, err)
		b.CloseWithError(net.ErrClosed)
		_, err = b.Read(make([]byte, 16))
		require.ErrorIs(t, err, net.ErrClosed)
		_, err = b.Write([]byte("bar"))
		require.ErrorIs(t, err, net.ErrClosed)
	})
}

func TestProxyNeedsAnHTTPStream(t *testing.T) {
	_, err := (&Proxy{}).Proxy(httptest.NewRecorder(), &ProxyRequest{})
	require.EqualError(t, err, "connect-ip: response writer is neither an HTTP/3 nor an HTTP/2 stream")
}
