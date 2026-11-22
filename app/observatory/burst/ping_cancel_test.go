package burst

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	"github.com/xtls/xray-core/transport/pipe"
)

type stalledHandshakeDispatcher struct {
	routing.Dispatcher
	address string
	done    chan error
}

func (d *stalledHandshakeDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	input, inputWriter := pipe.New()
	output, outputWriter := pipe.New()
	go func() {
		defer common.Interrupt(input)
		defer common.Interrupt(outputWriter)
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.address)
		if err != nil {
			d.done <- err
			return
		}
		defer raw.Close()
		d.done <- stdtls.Client(raw, &stdtls.Config{ServerName: "localhost"}).HandshakeContext(ctx)
	}()
	return &transport.Link{Reader: output, Writer: inputWriter}, nil
}

func TestProbeTimeoutCancelsPendingOutboundHandshake(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerClosed := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			peerClosed <- err
			return
		}
		defer peer.Close()
		peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		data := make([]byte, 4096)
		for {
			if _, err := peer.Read(data); err != nil {
				peerClosed <- err
				return
			}
		}
	}()
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance)))
	defer cancel()
	dispatcher := &stalledHandshakeDispatcher{address: listener.Addr().String(), done: make(chan error, 1)}
	client := newHTTPClient(parent, dispatcher, "stall", 200*time.Millisecond)
	response, err := client.Get("https://localhost/")
	if err == nil {
		response.Body.Close()
		t.Fatal("stalled probe unexpectedly succeeded")
	}
	select {
	case err := <-dispatcher.done:
		if err == nil {
			t.Fatal("stalled outbound unexpectedly completed its handshake")
		}
	case <-time.After(time.Second):
		t.Fatal("probe timed out but its outbound handshake kept running")
	}
	select {
	case err := <-peerClosed:
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("timed-out probe left the TCP socket open")
		}
	case <-time.After(time.Second):
		t.Fatal("timed-out probe left the TCP socket open")
	}
	if parent.Err() != nil {
		t.Fatal("probe timeout canceled the parent instance")
	}
}
