package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

// A malformed upstream response containing a bare '\n' before the real
// status line used to crash readResponseAndHandle100Continue: the first
// ReadSlice('\n') returns fewer than 4 bytes, and slicing
// ResponseHeader1xx[len(ResponseHeader1xx)-4:] panicked with a negative
// index instead of returning an error.
func TestReadResponseAndHandle100ContinueDoesNotPanicOnEarlyNewline(t *testing.T) {
	payload := "X\nHTTP/1.1 100 Continue\r\n\r\n" + strings.Repeat("A", 40)
	r := bufio.NewReader(bytes.NewReader([]byte(payload)))
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Must not panic; a parse error for the garbage trailing bytes is fine.
	_, _ = readResponseAndHandle100Continue(r, req, io.Discard)
}

func TestReadResponseAndHandle100ContinueForwardsAndParsesFinalResponse(t *testing.T) {
	payload := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	r := bufio.NewReader(iotest.OneByteReader(bytes.NewReader([]byte(payload))))
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	var forwarded bytes.Buffer
	resp, err := readResponseAndHandle100Continue(r, req, &forwarded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(forwarded.String(), "100 Continue") {
		t.Fatalf("expected 1xx response to be forwarded, got %q", forwarded.String())
	}
}

func TestForwardPlainHTTPAllowsBodyAfterContinue(t *testing.T) {
	client, downstream := newHTTPForwardTestConnection(t)
	upstream, origin := newHTTPForwardTestConnection(t)

	proxyDone := make(chan error, 1)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(downstream))
		if err == nil {
			err = forwardPlainHTTP(context.Background(), request, downstream, func(ctx context.Context, link *transport.Link) error {
				stop := context.AfterFunc(ctx, func() { upstream.Close() })
				defer stop()
				defer upstream.Close()
				// A router can inspect the serialized request before
				// forwarding it, then consume exactly the bytes it saw.
				prefix, err := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(time.Second)
				if err != nil {
					return err
				}
				header := prefix.String()
				if !strings.HasPrefix(header, "POST /upload?q=1 HTTP/1.1\r\n") ||
					!strings.Contains(header, "Host: proxy.test\r\n") {
					buf.ReleaseMulti(prefix)
					return fmt.Errorf("invalid serialized request prefix %q", header)
				}
				writer := buf.NewWriter(upstream)
				if err := writer.WriteMultiBuffer(prefix); err != nil {
					return err
				}
				return task.Run(ctx, func() error {
					return buf.Copy(link.Reader, writer)
				}, func() error {
					return buf.Copy(buf.NewReader(upstream), link.Writer)
				})
			})
		}
		proxyDone <- err
	}()

	originDone := make(chan error, 1)
	go func() {
		originDone <- func() error {
			request, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil {
				return err
			}
			defer request.Body.Close()
			if request.Method != "POST" || request.URL.RequestURI() != "/upload?q=1" ||
				request.Host != "proxy.test" || !request.Close || request.Header.Get("Expect") != "100-continue" {
				return fmt.Errorf("unexpected upstream request: %s %s host=%s close=%v expect=%q",
					request.Method, request.URL, request.Host, request.Close, request.Header.Get("Expect"))
			}
			if _, err := io.WriteString(origin, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return err
			}
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return err
			}
			if string(body) != "payload" {
				return fmt.Errorf("unexpected request body %q", body)
			}
			_, err = io.WriteString(origin, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			return err
		}()
	}()

	if _, err := io.WriteString(client, "POST http://proxy.test/upload?q=1 HTTP/1.1\r\nHost: proxy.test\r\nExpect: 100-continue\r\nContent-Length: 7\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	request := &http.Request{Method: http.MethodPost}
	interim, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	if interim.StatusCode != http.StatusContinue {
		t.Fatalf("interim status = %d, want 100", interim.StatusCode)
	}
	if _, err := io.WriteString(client, "payload"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "OK" || response.Close ||
		response.Header.Get("Proxy-Connection") != "keep-alive" {
		t.Fatalf("final response: status=%d body=%q close=%v proxy connection=%q",
			response.StatusCode, body, response.Close, response.Header.Get("Proxy-Connection"))
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
	if err := <-proxyDone; err != errWaitAnother {
		t.Fatalf("exchange returned %v, want reusable downstream connection", err)
	}
}

func TestForwardPlainHTTPClosesUnreadBodyAfterEarlyFinal(t *testing.T) {
	for _, tt := range []struct {
		name string
		wire string
		code int
	}{
		{
			name: "origin reply",
			wire: "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n",
			code: http.StatusExpectationFailed,
		},
		{
			name: "route ends without a response",
			code: http.StatusServiceUnavailable,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testPlainHTTPUnreadBodyClose(t, tt.wire, tt.code)
		})
	}
}

func testPlainHTTPUnreadBodyClose(t *testing.T, wire string, code int) {
	t.Helper()
	client, downstream := newHTTPForwardTestConnection(t)
	finished := make(chan error, 1)
	routeStopped := make(chan struct{})
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(downstream))
		if err == nil {
			err = forwardPlainHTTP(context.Background(), request, downstream, func(ctx context.Context, link *transport.Link) error {
				defer close(routeStopped)
				if wire == "" {
					return nil
				}
				// This origin answers before it needs any request body.
				if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte(wire))); err != nil {
					return err
				}
				<-ctx.Done()
				return nil
			})
		}
		finished <- err
	}()
	if _, err := io.WriteString(client, "POST http://proxy.test/upload HTTP/1.1\r\nHost: proxy.test\r\nExpect: 100-continue\r\nContent-Length: 7\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	reply, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	if reply.StatusCode != code || !reply.Close {
		t.Fatalf("status = %d, close = %v, want %d and connection close", reply.StatusCode, reply.Close, code)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("unread body left the downstream connection active: %v", err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request serializer was still blocked on the unread body")
	}
	select {
	case <-routeStopped:
	case <-time.After(5 * time.Second):
		t.Fatal("early final response did not cancel the selected route")
	}
}

func newHTTPForwardTestConnection(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Until(deadline))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	for _, conn := range []net.Conn{client, server} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}
