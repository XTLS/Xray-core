package shadowsocks_2022_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/policy"
	. "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func transportPolicy() policy.Session {
	p := policy.SessionDefault()
	p.Timeouts.ConnectionIdle = 5 * time.Second
	p.Timeouts.DownlinkOnly = 5 * time.Second
	p.Timeouts.UplinkOnly = 5 * time.Second
	return p
}

func TestTransportTCPRequestEOF(t *testing.T) {
	input, inputWriter := pipe.New(pipe.WithSizeLimit(-1))
	request, requestWriter := pipe.New(pipe.WithSizeLimit(-1))
	response, responseWriter := pipe.New(pipe.WithSizeLimit(-1))
	defer input.Interrupt()
	defer request.Interrupt()
	defer response.Interrupt()
	payload := bytes.Repeat([]byte("buffered request"), 512)
	if err := inputWriter.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
		t.Fatal(err)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- TransportTCP(context.Background(), transportPolicy(), input, buf.NewWriter(&received), &transport.Link{Reader: response, Writer: requestWriter})
	}()
	mb, err := request.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := mb.String(); got != string(payload) {
		buf.ReleaseMulti(mb)
		t.Fatal("request lost buffered bytes")
	}
	buf.ReleaseMulti(mb)
	mb, err = request.ReadMultiBufferTimeout(time.Second)
	buf.ReleaseMulti(mb)
	if err != io.EOF {
		t.Fatalf("request EOF not forwarded: %v", err)
	}
	// The peer waits for request EOF before preparing its final response.
	time.Sleep(150 * time.Millisecond)
	if err := responseWriter.WriteMultiBuffer(buf.MergeBytes(nil, []byte("delayed ACK"))); err != nil {
		t.Fatalf("response half closed on request EOF: %v", err)
	}
	if err := responseWriter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport did not finish after both EOFs")
	}
	if received.String() != "delayed ACK" {
		t.Fatalf("final response: %q", received.String())
	}
}

func TestTransportTCPAbort(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request, requestWriter := pipe.New()
	response, responseWriter := pipe.New()
	defer request.Interrupt()
	defer response.Interrupt()
	done := make(chan error, 1)
	go func() {
		done <- TransportTCP(context.Background(), transportPolicy(), buf.NewReader(server), buf.Discard, &transport.Link{Reader: response, Writer: requestWriter})
	}()
	if err := client.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reset must fail the request copy")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not end transport")
	}
	assertDispatchInterrupted(t, request, responseWriter)
}

func TestTransportTCPCancel(t *testing.T) {
	input, _ := pipe.New()
	request, requestWriter := pipe.New()
	response, responseWriter := pipe.New()
	defer input.Interrupt()
	defer request.Interrupt()
	defer response.Interrupt()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- TransportTCP(ctx, transportPolicy(), input, buf.Discard, &transport.Link{Reader: response, Writer: requestWriter})
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not end transport")
	}
	assertDispatchInterrupted(t, request, responseWriter)
}

func assertDispatchInterrupted(t *testing.T, request *pipe.Reader, response *pipe.Writer) {
	t.Helper()
	mb, err := request.ReadMultiBufferTimeout(time.Second)
	buf.ReleaseMulti(mb)
	if err != io.ErrClosedPipe {
		t.Errorf("request pipe still alive after transport return: %v", err)
	}
	if err := response.WriteMultiBuffer(buf.MergeBytes(nil, []byte("late response"))); err != io.ErrClosedPipe {
		t.Errorf("response pipe still alive after transport return: %v", err)
	}
}
