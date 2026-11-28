package dns

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	wiredns "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/signal"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsUDPAdmissionCounter struct {
	stats.Counter
	attempted chan struct{}
}

func (c *dnsUDPAdmissionCounter) Add(bytes int64) int64 {
	total := c.Counter.Add(bytes)
	c.attempted <- struct{}{}
	return total
}

func TestUDPNameServerCanceledAdmissionKeepsSibling(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	route, retire := context.WithCancel(ctx)
	defer retire()
	server := NewClassicNameServer(net.UDPDestination(net.LocalHostIP, 53), nil, false, false, 0, nil)
	defer server.requestsCleanup.Close()
	exchange := &dnsUDPExchange{ctx: route, cancel: retire, inbox: udp.NewPacketInbox(0)}
	exchange.timer = signal.CancelAfterInactivity(route, retire, time.Minute)
	defer exchange.timer.SetTimeout(0)
	defer exchange.inbox.Close()
	server.exchange = exchange
	exchange.inbox.AttachRoute(route)
	counter := &dnsUDPAdmissionCounter{attempted: make(chan struct{}, 2)}
	exchange.inbox.BindUplinkCounter(route, counter)

	const siblingName = "sibling.example."
	option := featureDNS.IPOption{IPv4Enable: true}
	sibling, _ := server.cacheController.registerSubscribers(siblingName, option)
	defer sibling.Close()
	server.sendQuery(ctx, nil, siblingName, option)
	<-counter.attempted

	query, cancel := context.WithCancel(ctx)
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		_, _, err := server.QueryIP(query, "blocked.example", option)
		returned <- err
	}()
	select {
	case <-counter.attempted:
	case <-ctx.Done():
		t.Fatal("query did not try to enter the full inbox")
	}
	// Reacquire the inbox lock after the attempt counter recorded the
	// query. Admission cannot have finished while the first packet is held.
	exchange.inbox.BindUplinkCounter(route, counter)
	server.RLock()
	pending := len(server.requests)
	server.RUnlock()
	if pending != 2 {
		t.Fatalf("pending requests before cancellation = %d, want 2", pending)
	}
	cancel()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("canceled query reported success")
		}
	case <-ctx.Done():
		t.Fatal("canceled query stayed blocked while the outbound was stalled")
	}
	exchangeAfterCancel, err := server.getExchange(ctx)
	if err != nil || exchangeAfterCancel != exchange {
		t.Fatalf("query cancellation retired the shared exchange: %v", err)
	}
	server.RLock()
	pending = len(server.requests)
	server.RUnlock()
	if pending != 1 {
		t.Fatalf("pending requests after cancellation = %d, want 1", pending)
	}

	reader := udp.NewDispatchPacketReader(route, retire, exchange.inbox, nil)
	packets, err := reader.ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(packets)
	if err != nil || len(packets) != 1 {
		t.Fatalf("sibling query stalled or was delivered with an extra packet: %v (%d packets)", err, len(packets))
	}
	var response dnsmessage.Message
	if err := response.Unpack(packets[0].Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(response.Questions) != 1 || response.Questions[0].Name.String() != siblingName {
		t.Fatalf("got questions %v, want the sibling alone", response.Questions)
	}
	response.Response = true
	response.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: response.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 54}},
	}}
	reply, err := wiredns.PackMessage(&response)
	if err != nil {
		t.Fatal(err)
	}
	writer := &dnsUDPResponseWriter{server: server, exchange: exchange}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{reply}); err != nil {
		t.Fatal(err)
	}
	select {
	case record := <-sibling.Wait():
		ips := record.(*IPRecord).IP
		if len(ips) != 1 || ips[0].String() != "192.0.2.54" {
			t.Fatalf("sibling response was %v", ips)
		}
	case <-ctx.Done():
		t.Fatal("sibling received no response")
	}
}
