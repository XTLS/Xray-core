package xdns

import (
	"bytes"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

func TestEncryptedClientDeadlineAndClose(t *testing.T) {
	client, err := NewClient(&Config{
		Domains:   []*DomainProto{{Name: "tunnel.example", LenLimit: 255, LabelLimit: 63}},
		Resolvers: []*ResolverProto{{Type: "dot", Addr: "127.0.0.1:853"}},
	}, testResolverDialer())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFrom(make([]byte, 4096)); err != os.ErrDeadlineExceeded {
		t.Fatalf("read returned %v", err)
	}
	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo([]byte{1}, nil); err != os.ErrDeadlineExceeded {
		t.Fatalf("write returned %v", err)
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := client.ReadFrom(make([]byte, 4096)); done <- err }()
	// Changing an already-blocked read's deadline must wake that read.
	if err := client.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != os.ErrDeadlineExceeded {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline update did not wake ReadFrom")
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFrom(make([]byte, 4096)); err != io.ErrClosedPipe {
		t.Fatalf("closed read returned %v", err)
	}
}

func TestClientValidatesResolverListBeforeDial(t *testing.T) {
	dialer := &finalmask.Dialer{DialUDP: func(net.Destination) (net.Conn, error) {
		t.Fatal("dialed before validating the entire list")
		return nil, nil
	}}
	_, err := NewClient(&Config{
		Domains:   []*DomainProto{{Name: "tunnel.example", LenLimit: 255, LabelLimit: 63}},
		Resolvers: []*ResolverProto{{Type: "udp", Addr: "127.0.0.1:53"}, {Type: "dot", Addr: "host:0"}},
	}, dialer)
	if err == nil {
		t.Fatal("invalid resolver list accepted")
	}
}

type captureResolver struct{ queries chan []byte }

func (r *captureResolver) Addr() *net.UDPAddr       { return &net.UDPAddr{} }
func (r *captureResolver) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (r *captureResolver) Send(p []byte)            { r.queries <- append([]byte(nil), p...) }
func (r *captureResolver) Close()                   {}

func TestClientPollingDoesNotReplayPayload(t *testing.T) {
	domain, err := NewDomain("tunnel.example", 255, 63, []uint16{TypeTXT}, 0)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &captureResolver{queries: make(chan []byte, 16)}
	client := &xdnsClient{
		clientID: NewClientID(), domains: []*Domain{domain},
		resolvers: []Resolver{resolver}, resolverSends: make([]atomic.Uint32, 1),
		sendCh: make(chan []byte, 16), poolCh: make(chan struct{}, 16), closeCh: make(chan struct{}),
	}
	client.wg.Add(1)
	go client.send()
	defer func() { close(client.closeCh); client.wg.Wait() }()
	payload := []byte("send exactly once")
	client.sendCh <- payload
	for i := range 2 {
		select {
		case query := <-resolver.queries:
			var msg dnsmessage.Message
			if err := msg.Unpack(query); err != nil {
				t.Fatal(err)
			}
			var decoded [255]byte
			n := domain.Decode(&decoded, msg.Questions[0].Name)
			if i == 0 && (n != len(payload)+12 || !bytes.Equal(decoded[12:n], payload)) {
				t.Fatal("initial query did not contain payload")
			}
			if i == 1 && (n != 17 || decoded[8] != 8) {
				t.Fatal("polling replayed a previous payload")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("query did not arrive")
		}
	}
}
