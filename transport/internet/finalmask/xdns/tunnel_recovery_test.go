package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

func recoveryTunnel(t *testing.T) (*DomainProto, *xdnsServer, func(context.Context, []byte) ([]byte, error), <-chan tunnelObserved) {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	domain := &DomainProto{Name: "recovery.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}
	packetServer, err := NewServer(&Config{Domains: []*DomainProto{domain}}, raw)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	server := packetServer.(*xdnsServer)
	observed := make(chan tunnelObserved, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p := make([]byte, 4096)
		for {
			n, addr, err := server.ReadFrom(p)
			if err != nil {
				return
			}
			data := bytes.Clone(p[:n])
			_, err = server.WriteTo(tunnelReply(data), addr)
			observed <- tunnelObserved{data: data, address: addr.String(), err: err}
		}
	}()
	t.Cleanup(func() {
		server.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("tunnel server reader did not close")
		}
	})
	forward := func(ctx context.Context, query []byte) ([]byte, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", raw.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		deadline := time.Now().Add(resolverRequestTimeout)
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
		conn.SetDeadline(deadline)
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		p := make([]byte, maxDNSMessageSize+1)
		n, err := conn.Read(p)
		if n > maxDNSMessageSize {
			return nil, errors.New("oversized response")
		}
		return p[:n], err
	}
	return domain, server, forward, observed
}

func recoveryClient(t *testing.T, domain *DomainProto, resolver *ResolverProto, dialer *finalmask.Dialer, extra int32) (net.PacketConn, <-chan tunnelObserved) {
	t.Helper()
	client, err := NewClient(&Config{Domains: []*DomainProto{domain}, Resolvers: []*ResolverProto{resolver}, ExtraPoll: extra}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan tunnelObserved, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p := make([]byte, 4096)
		for {
			n, _, err := client.ReadFrom(p)
			if err != nil {
				return
			}
			observed <- tunnelObserved{data: bytes.Clone(p[:n])}
		}
	}()
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { client.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Error("tunnel client Close did not return")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("tunnel client reader did not close")
		}
	})
	return client, observed
}

func recoveryReceive(t *testing.T, observed <-chan tunnelObserved, want []byte) tunnelObserved {
	t.Helper()
	select {
	case packet := <-observed:
		if packet.err != nil || !bytes.Equal(packet.data, want) {
			t.Fatalf("packet mismatch: got %x, want %x, error %v", packet.data, want, packet.err)
		}
		return packet
	case <-time.After(7 * time.Second):
		t.Fatal("tunnel packet did not arrive")
		return tunnelObserved{}
	}
}

func recoveryDecoded(domain *Domain, query []byte) ([]byte, error) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil || len(message.Questions) != 1 {
		return nil, errors.New("invalid tunnel query")
	}
	var decoded [255]byte
	n := domain.Decode(&decoded, message.Questions[0].Name)
	if n < 9 {
		return nil, errors.New("invalid tunnel payload")
	}
	return bytes.Clone(decoded[:n]), nil
}

func TestXDNSIdlePollBackoffAndQueueExpiry(t *testing.T) {
	for _, extra := range []int32{0, 3} {
		t.Run(fmt.Sprintf("ExtraPoll=%d", extra), func(t *testing.T) {
			t.Parallel()
			domain, server, forward, uplink := recoveryTunnel(t)
			polls := make(chan time.Time, 128)
			completed := make(chan error, 128)
			_, resolver, dialer := startDoHTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				query, err := io.ReadAll(io.LimitReader(req.Body, maxDNSMessageSize+1))
				decoded, decodeErr := recoveryDecoded(server.domains[0], query)
				poll := decodeErr == nil && decoded[8]&0x3f == 8
				if poll {
					polls <- time.Now()
				}
				if err != nil || decodeErr != nil {
					http.Error(w, "invalid query", http.StatusBadRequest)
					return
				}
				response, err := forward(req.Context(), query)
				if poll {
					completed <- err
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(response)
			}))
			client, downlink := recoveryClient(t, domain, resolver, dialer, extra)
			seed := []byte("start-idle-polling")
			if _, err := client.WriteTo(seed, nil); err != nil {
				t.Fatal(err)
			}
			recoveryReceive(t, downlink, tunnelReply(seed))
			seedReceived := time.Now()
			recoveryReceive(t, uplink, seed)
			readBurst := func(count int) time.Time {
				var first time.Time
				for range count {
					select {
					case at := <-polls:
						if first.IsZero() {
							first = at
						}
					case <-time.After(12 * time.Second):
						t.Fatal("expected wire poll burst did not arrive")
					}
				}
				return first
			}
			burst := int(extra + 1)
			// WriteTo emits ExtraPoll polls; the first downlink starts the 500ms ticker.
			if extra > 0 {
				readBurst(int(extra))
			}
			previous := readBurst(burst)
			initial := previous.Sub(seedReceived)
			t.Logf("first wire poll after seed=%s expected=500ms; WriteTo polls=%d tick burst=%d", initial, extra, burst)
			if initial < 400*time.Millisecond || initial > 2500*time.Millisecond {
				t.Fatalf("unexpected initial idle poll delay: %s", initial)
			}
			count := int(extra) + burst
			for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second} {
				at := readBurst(burst)
				interval := at.Sub(previous)
				t.Logf("wire poll interval=%s expected=%s burst=%d", interval, want, burst)
				if interval < want*8/10 || interval > want+2*time.Second {
					t.Fatalf("unexpected idle backoff interval %s, expected %s", interval, want)
				}
				previous = at
				count += burst
			}
			// Wait for actual empty DNS responses so the new downlink cannot ride an active poll.
			for range count {
				select {
				case err := <-completed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("idle poll did not finish")
				}
			}
			id := client.(*xdnsClient).clientID
			queued := time.Now()
			lost := []byte("expires-before-ten-second-poll")
			if _, err := server.WriteTo(lost, id.Addr()); err != nil {
				t.Fatal(err)
			}
			server.sendManager.mu.Lock()
			deadline := server.sendManager.m[id].deadline
			server.sendManager.mu.Unlock()
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			expiryLimit := time.NewTimer(time.Until(deadline) + sendTTL + time.Second)
			defer expiryLimit.Stop()
		waitExpiry:
			for {
				select {
				case <-ticker.C:
					server.sendManager.mu.Lock()
					_, exists := server.sendManager.m[id]
					server.sendManager.mu.Unlock()
					if !exists {
						t.Logf("idle downlink lost after %s; queue deadline was %s after enqueue, TTL=%s", time.Since(queued), deadline.Sub(queued), sendTTL)
						break waitExpiry
					}
				case <-expiryLimit.C:
					t.Fatal("idle downlink queue did not expire under the configured TTL")
				case packet := <-downlink:
					t.Fatalf("idle packet unexpectedly delivered before next wire poll: %x", packet.data)
				}
			}
			at := readBurst(burst)
			interval := at.Sub(previous)
			t.Logf("capped wire poll interval=%s burst=%d", interval, burst)
			if interval < 8*time.Second || interval > 12*time.Second {
				t.Fatalf("poll did not reach the ten-second cap: %s", interval)
			}
			select {
			case packet := <-downlink:
				t.Fatalf("expired queue data arrived: %x", packet.data)
			default:
			}
			fresh := []byte("idle-queue-recovery")
			if _, err := client.WriteTo(fresh, nil); err != nil {
				t.Fatal(err)
			}
			recoveryReceive(t, downlink, tunnelReply(fresh))
			recoveryReceive(t, uplink, fresh)
		})
	}
}

func TestXDNSHTTPSOutageRecoversTwoClientsWithoutReplay(t *testing.T) {
	domain, server, forward, uplink := recoveryTunnel(t)
	var outage atomic.Bool
	started := make(chan string, 2)
	cancelled := make(chan string, 2)
	var callsMu sync.Mutex
	calls := make(map[string]int)
	certificate, pem := resolverTestCertificate(t)
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		query, err := io.ReadAll(io.LimitReader(req.Body, maxDNSMessageSize+1))
		decoded, decodeErr := recoveryDecoded(server.domains[0], query)
		if err != nil || decodeErr != nil {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		if decoded[8]&0x3f == 3 && len(decoded) >= 12 {
			data := string(decoded[12:])
			callsMu.Lock()
			calls[data]++
			callsMu.Unlock()
			if outage.Load() && bytes.HasPrefix(decoded[12:], []byte("outage/")) {
				started <- data
				<-req.Context().Done()
				cancelled <- data
				return
			}
		}
		response, err := forward(req.Context(), query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(response)
	}))
	gateway.EnableHTTP2 = true
	gateway.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	gateway.StartTLS()
	t.Cleanup(gateway.Close)
	_, port, err := net.SplitHostPort(gateway.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver := &ResolverProto{Type: "https", Addr: "https://resolver.test:" + port + "/dns-query", Bootstrap: "127.0.0.1", Certificates: []*xtls.Certificate{{Certificate: pem, Usage: xtls.Certificate_AUTHORITY_VERIFY}}}
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
	}}
	clients := make([]net.PacketConn, 2)
	downlinks := make([]<-chan tunnelObserved, 2)
	addresses := make([]string, 2)
	for i := range clients {
		clients[i], downlinks[i] = recoveryClient(t, domain, resolver, dialer, 0)
	}
	t.Cleanup(func() {
		if t.Failed() {
			callsMu.Lock()
			t.Logf("data requests actually accepted by HTTPS gateway: %v", calls)
			callsMu.Unlock()
		}
	})
	transfer := func(phase string) {
		for sequence := range 3 {
			for i, client := range clients {
				data := []byte(fmt.Sprintf("%s/client=%d/sequence=%d/\x00\xff", phase, i, sequence))
				if _, err := client.WriteTo(data, nil); err != nil {
					t.Fatal(err)
				}
				recoveryReceive(t, downlinks[i], tunnelReply(data))
				packet := recoveryReceive(t, uplink, data)
				if addresses[i] != "" && addresses[i] != packet.address {
					t.Fatal("client response attribution changed after reconnect")
				}
				addresses[i] = packet.address
			}
		}
	}
	transfer("before")
	if addresses[0] == addresses[1] {
		t.Fatal("two clients shared their response address")
	}
	outage.Store(true)
	for i, client := range clients {
		if _, err := client.WriteTo([]byte(fmt.Sprintf("outage/client=%d", i)), nil); err != nil {
			t.Fatal(err)
		}
	}
	for range clients {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("outage request did not start before the cut")
		}
	}
	outage.Store(false)
	gateway.CloseClientConnections()
	for range clients {
		select {
		case name := <-cancelled:
			t.Logf("accepted HTTPS connection cut cancelled %s", name)
		case <-time.After(3 * time.Second):
			t.Fatal("cut request did not observe cancellation")
		}
	}
	// Server cancellation precedes client pool teardown; a completed poll proves that client's route is ready.
	for i, client := range clients {
		probeCtx, stopProbe := context.WithTimeout(t.Context(), resolverRequestTimeout)
		data := make([]byte, 17)
		copy(data, client.(*xdnsClient).clientID[:])
		data[0] |= TypeMap[TypeTXT]
		data[8] = 8
		var ready bool
		var probeErr error
		for attempt := range 3 {
			data[9] = byte(attempt + 1)
			message := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(attempt + 1)}, Questions: []dnsmessage.Question{{Name: server.domains[0].Encode(data), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
			query, err := message.Pack()
			if err != nil {
				stopProbe()
				t.Fatal(err)
			}
			response, err := client.(*xdnsClient).resolvers[0].(*requestResolver).exchange(probeCtx, query)
			if err == nil {
				err = validateDNSResponse(query, response)
			}
			if err == nil {
				var reply dnsmessage.Message
				if err := reply.Unpack(response); err != nil {
					stopProbe()
					t.Fatal(err)
				}
				var decoded [4096]byte
				if n := NewResp(reply, server.domains[0], 0).Decode(decoded[:]); n != 0 {
					stopProbe()
					t.Fatalf("recovery poll consumed unexpected application data: %x", decoded[:n])
				}
				ready = true
				t.Logf("client %d recovery-ready poll completed on attempt %d", i, attempt+1)
				break
			}
			probeErr = err
			t.Logf("client %d teardown poll attempt %d failed: %v", i, attempt+1, err)
		}
		stopProbe()
		if !ready {
			t.Fatalf("client %d route did not recover before payload submission: %v", i, probeErr)
		}
	}
	transfer("after")
	// This is a bounded observation window for extra deliveries, not a readiness delay.
	window := time.NewTimer(time.Second)
	defer window.Stop()
	select {
	case packet := <-uplink:
		t.Fatalf("unrequested replay/duplicate uplink: %x", packet.data)
	case packet := <-downlinks[0]:
		t.Fatalf("duplicate or misattributed client 0 response: %x", packet.data)
	case packet := <-downlinks[1]:
		t.Fatalf("duplicate or misattributed client 1 response: %x", packet.data)
	case <-window.C:
	}
	callsMu.Lock()
	defer callsMu.Unlock()
	for i := range clients {
		key := fmt.Sprintf("outage/client=%d", i)
		if calls[key] != 1 {
			t.Fatalf("outage payload replayed at gateway: %s calls=%d", key, calls[key])
		}
	}
	for data, count := range calls {
		if count != 1 {
			t.Fatalf("data request was replayed at gateway: %q calls=%d", data, count)
		}
	}
	t.Log("outage loss: 2 submitted uplinks intentionally cut before forwarding; both clients recovered 3 exact sequence packets each")
}

type recoveryWirePacketConn struct {
	net.PacketConn
	read chan struct{}
}

func (c *recoveryWirePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.read <- struct{}{}
	}
	return n, addr, err
}

func TestXDNSWireFragmentRecoveryExpiryAndClose(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &recoveryWirePacketConn{PacketConn: raw, read: make(chan struct{}, 32)}
	proto := &DomainProto{Name: "fragments.test", LenLimit: 255, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}
	packetServer, err := NewServer(&Config{Domains: []*DomainProto{proto}}, tracked)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	server := packetServer.(*xdnsServer)
	t.Cleanup(func() { server.Close() })
	client, err := net.Dial("udp", raw.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	observed := make(chan tunnelObserved, 16)
	readerDone := make(chan error, 1)
	go func() {
		p := make([]byte, 4096)
		for {
			n, _, err := server.ReadFrom(p)
			if err != nil {
				readerDone <- err
				return
			}
			observed <- tunnelObserved{data: bytes.Clone(p[:n])}
		}
	}()
	id := ClientID{0x20, 1, 2, 3, 4, 5, 6, 7}
	var queryID uint16
	writeQuery := func(data []byte, awaitResponse bool) {
		queryID++
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: queryID}, Questions: []dnsmessage.Question{{Name: server.domains[0].Encode(data), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
		query, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(query); err != nil {
			t.Fatal(err)
		}
		select {
		case <-tracked.read:
		case <-time.After(time.Second):
			t.Fatal("server did not receive the wire query")
		}
		if awaitResponse {
			p := make([]byte, 4096)
			n, err := client.Read(p)
			if err != nil {
				t.Fatal(err)
			}
			var reply dnsmessage.Message
			if err := reply.Unpack(p[:n]); err != nil || !reply.Response || reply.ID != queryID {
				t.Fatalf("invalid fragment DNS acknowledgement: %v", err)
			}
		}
	}
	fragment := func(group, index, total byte, content string) {
		data := make([]byte, 15, 15+len(content))
		copy(data, id[:])
		data[0] |= TypeMap[TypeTXT]
		data[8] = 3 | 0xc0
		data[12], data[13], data[14] = group, index, total
		writeQuery(append(data, content...), true)
	}
	noPacket := func() {
		select {
		case packet := <-observed:
			t.Fatalf("incomplete, duplicate, or stale group delivered: %x", packet.data)
		default:
		}
	}
	fragment(42, 2, 3, "cc")
	fragment(42, 1, 3, "bb")
	fragment(42, 1, 3, "duplicate-must-not-replace-bb")
	noPacket()
	fragment(42, 0, 3, "aa")
	recoveryReceive(t, observed, []byte("aabbcc"))
	noPacket()
	fragment(43, 0, 3, "expired-first")
	fragment(43, 2, 3, "expired-last")
	noPacket()
	expiryStart := time.Now()
	timer := time.NewTimer(fragTTL + 100*time.Millisecond)
	select {
	case <-timer.C:
	case packet := <-observed:
		timer.Stop()
		t.Fatalf("omitted fragment group delivered: %x", packet.data)
	}
	t.Logf("real fragment expiry wait=%s, TTL=%s", time.Since(expiryStart), fragTTL)
	fragment(43, 1, 3, "late-middle")
	noPacket()
	fragment(44, 1, 2, "group")
	fragment(44, 0, 2, "fresh-")
	recoveryReceive(t, observed, []byte("fresh-group"))
	noPacket()
	// Leave an actual poll active while the application reader waits for another datagram.
	poll := make([]byte, 17)
	copy(poll, id[:])
	poll[0] |= TypeMap[TypeTXT]
	poll[8] = 8
	writeQuery(poll, false)
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("server Close did not return during an active query")
	}
	select {
	case err := <-readerDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("closed application reader: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked server ReadFrom or query workers did not release")
	}
	for _, done := range []<-chan struct{}{server.fragManager.ch, server.sendManager.ch} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("server retained a fragment/queue worker after Close")
		}
	}
}
