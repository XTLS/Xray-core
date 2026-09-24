package connectip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
