package xdns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func capacityTestDomain() *Domain {
	domain, err := NewDomain("tunnel.test", 255, 63, []uint16{1, 5, 16, 28}, 4096)
	if err != nil {
		panic(err)
	}
	return domain
}

type capacityRecordingResolver struct {
	Resolver
	accepted atomic.Int32
}

func (r *capacityRecordingResolver) Send(query []byte) error {
	if err := r.Resolver.Send(query); err != nil {
		return err
	}
	r.accepted.Add(1)
	return nil
}

func capacityTestQuery(t *testing.T, domain *Domain, qtype uint16, id ClientID, edns0 uint16) ([]byte, dnsmessage.Message) {
	t.Helper()
	data := make([]byte, 17)
	copy(data, id[:])
	data[0] |= TypeMap[qtype]
	data[8] = 8
	for i := 9; i < len(data); i++ {
		data[i] = byte(i)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: domain.Encode(data), Type: dnsmessage.Type(qtype), Class: dnsmessage.ClassINET}},
	}
	if edns0 > 0 {
		msg.Additionals = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(edns0)},
			Body:   &dnsmessage.OPTResource{},
		}}
	}
	packet, err := msg.AppendPack(nil)
	if err != nil {
		t.Fatal(err)
	}
	return packet, msg
}

func exchangeCapacityPoll(t *testing.T, raw net.PacketConn, server net.PacketConn, query []byte, id ClientID, payload []byte) ([]byte, dnsmessage.Message) {
	t.Helper()
	conn, err := net.Dial("udp4", raw.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	if n, err := server.WriteTo(payload, id.Addr()); err != nil || n != len(payload) {
		t.Fatalf("server.WriteTo(%d) = %d, %v", len(payload), n, err)
	}
	buf := make([]byte, 4097)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n > 4096 {
		t.Fatalf("DNS response has %d bytes", n)
	}
	var response dnsmessage.Message
	if err := response.Unpack(buf[:n]); err != nil {
		t.Fatalf("invalid DNS response: %v", err)
	}
	return buf[:n], response
}

func decodeCapacityPayload(t *testing.T, response dnsmessage.Message, domain *Domain) []byte {
	t.Helper()
	decoded := make([]byte, 4096)
	n := NewResp(response, domain, 0).Decode(decoded)
	if n == 0 {
		return nil
	}
	if n < 2 || (int(decoded[0]&0x3f)<<8|int(decoded[1])) > n-2 || decoded[0]&0x40 == 0 {
		t.Fatalf("invalid tunnel response frame: %x", decoded[:n])
	}
	size := int(decoded[0]&0x3f)<<8 | int(decoded[1])
	return decoded[2 : 2+size]
}

func TestServerDownlinkHonorsEDNSAndResponseCapacity(t *testing.T) {
	for _, qtype := range []uint16{1, 5, 16, 28} {
		for _, advertised := range []uint16{0, 512, 1232, 4096} {
			t.Run(fmt.Sprintf("type-%d/edns-%d", qtype, advertised), func(t *testing.T) {
				domain := capacityTestDomain()
				raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewServer(&Config{Domains: []*DomainProto{{Name: "tunnel.test", LenLimit: 255, LabelLimit: 63, Types: []int32{int32(qtype)}, Edns0: 4096}}}, raw)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				defer server.Close()

				id := ClientID{0x40, 2, 3, 4, 5, 6, 7, 8}
				query, msg := capacityTestQuery(t, domain, qtype, id, advertised)
				maxDNSSize := int(min(max(advertised, 512), 4096))
				cap := NewResp(msg, domain, advertised).cap
				maxPayload := cap - 2
				if maxPayload < 1 {
					t.Fatalf("nonpositive response payload capacity: cap=%d", cap)
				}
				if qtype == 16 && advertised == 4096 {
					t.Logf("largest TXT response uses %d bytes (NewResp.cap=%d), advertised maximum is 4096", maxPayload, cap)
					if maxPayload <= 83 {
						t.Fatalf("large downlink sample is only %d bytes", maxPayload)
					}
				}
				payload := make([]byte, maxPayload)
				for i := range payload {
					payload[i] = byte(i*31 + 7)
				}
				wire, response := exchangeCapacityPoll(t, raw, server, query, id, payload)
				if len(wire) > maxDNSSize {
					t.Fatalf("response size %d exceeds negotiated EDNS limit %d", len(wire), maxDNSSize)
				}
				if decoded := decodeCapacityPayload(t, response, domain); !bytes.Equal(decoded, payload) {
					t.Fatal("maximum-capacity downlink changed payload")
				}

				query, _ = capacityTestQuery(t, domain, qtype, id, advertised)
				tooLarge := make([]byte, cap-1)
				_, oversizedResponse := exchangeCapacityPoll(t, raw, server, query, id, tooLarge)
				if decoded := NewResp(oversizedResponse, domain, 0).Decode(make([]byte, 4096)); decoded != 0 {
					t.Fatalf("capacity+1 response unexpectedly carried %d tunnel bytes", decoded)
				}

				query, _ = capacityTestQuery(t, domain, qtype, id, advertised)
				small := []byte("ok")
				_, recovered := exchangeCapacityPoll(t, raw, server, query, id, small)
				if decoded := decodeCapacityPayload(t, recovered, domain); !bytes.Equal(decoded, small) {
					t.Fatalf("response did not recover after oversized queue item: %q", decoded)
				}
			})
		}
	}
}

func TestClientCharacterizesMaxUplinkResolverQueueLimit(t *testing.T) {
	domain := &DomainProto{Name: "tunnel.test", LenLimit: 96, LabelLimit: 63, Types: []int32{16}, Edns0: 4096}
	serverRaw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(&Config{Domains: []*DomainProto{domain}}, serverRaw)
	if err != nil {
		serverRaw.Close()
		t.Fatal(err)
	}
	defer server.Close()
	decodedDomain, err := NewDomain(domain.Name, int(domain.LenLimit), int(domain.LabelLimit), []uint16{16}, uint16(domain.Edns0))
	if err != nil {
		t.Fatal(err)
	}
	chunkSize := decodedDomain.cap - 15
	fragmentCount := (4096 + chunkSize - 1) / chunkSize
	if decodedDomain.cap != 50 || chunkSize != 35 || fragmentCount != 118 {
		t.Fatalf("uplink geometry: cap=%d chunk=%d fragments=%d, want 50/35/118", decodedDomain.cap, chunkSize, fragmentCount)
	}
	t.Logf("4096-byte uplink: domain cap=%d, payload per fragment=%d, expected DNS fragments=%d; resolver workers=%d plus queue=%d", decodedDomain.cap, chunkSize, fragmentCount, resolverConcurrency, resolverQueueSize)
	uplink := make([]byte, 4096)
	for i := range uplink {
		uplink[i] = byte(i*37 + 11)
	}

	gate := make(chan struct{})
	var releaseOnce sync.Once
	releaseGateway := func() { releaseOnce.Do(func() { close(gate) }) }
	defer releaseGateway()
	var queryFragments atomic.Int32
	var declaredFragments atomic.Int32
	var fragmentMu sync.Mutex
	seenFragments := make(map[byte]struct{})
	fragmentsCompleted := make(chan struct{}, resolverConcurrency+resolverQueueSize)
	resolver, dialer := startDoTGateway(t, func(ctx context.Context, query []byte) ([]byte, error) {
		var msg dnsmessage.Message
		if err := msg.Unpack(query); err != nil {
			return nil, err
		}
		var encoded [255]byte
		n := decodedDomain.Decode(&encoded, msg.Questions[0].Name)
		if n > 15 && encoded[8]&0xC0 == 0xC0 {
			index := int(encoded[13])
			if int(encoded[14]) != fragmentCount || index >= fragmentCount || !bytes.Equal(encoded[15:n], uplink[index*chunkSize:min((index+1)*chunkSize, len(uplink))]) {
				return nil, fmt.Errorf("fragment %d/%d changed uplink data", index, encoded[14])
			}
			queryFragments.Add(1)
			declaredFragments.Store(int32(encoded[14]))
			fragmentMu.Lock()
			seenFragments[encoded[13]] = struct{}{}
			fragmentMu.Unlock()
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", serverRaw.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		response := make([]byte, 4096)
		n, err = conn.Read(response)
		if err == nil && encoded[8]&0xC0 == 0xC0 {
			fragmentsCompleted <- struct{}{}
		}
		return response[:n], err
	})
	transport, err := NewResolver(resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	recorded := &capacityRecordingResolver{Resolver: transport}
	// Install the recorder before run starts; replacing a running NewClient's resolver would race.
	client := &xdnsClient{
		dialer:        dialer,
		clientID:      NewClientID(),
		domains:       []*Domain{decodedDomain},
		resolvers:     []Resolver{recorded},
		resolverSends: make([]atomic.Uint32, 1),
		readCh:        make(chan packet),
		poolCh:        make(chan struct{}, pollLimit),
		closeCh:       make(chan struct{}),
	}
	client.wg.Add(2)
	go client.run()

	type tunnelPacket struct {
		data []byte
		addr net.Addr
		err  error
	}
	startReader := func() (chan tunnelPacket, chan struct{}) {
		received := make(chan tunnelPacket, 1)
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			buf := make([]byte, 4096)
			n, addr, err := server.ReadFrom(buf)
			received <- tunnelPacket{data: append([]byte(nil), buf[:n]...), addr: addr, err: err}
		}()
		return received, readerDone
	}
	received, readerDone := startReader()
	defer func() {
		releaseGateway()
		_ = client.Close()
		_ = server.Close()
		select {
		case <-readerDone:
		case <-time.After(time.Second):
			t.Error("server reader did not stop")
		}
	}()
	_, sendErr := client.WriteTo(uplink, nil)
	if sendErr == nil || sendErr.Error() != "xdns resolver request queue is full" {
		t.Fatalf("4096-byte xdns client.WriteTo = %v, want resolver queue full", sendErr)
	}
	accepted := int(recorded.accepted.Load())
	if accepted < resolverQueueSize || accepted > resolverConcurrency+resolverQueueSize || accepted >= fragmentCount {
		t.Fatalf("accepted %d fragments, want %d..%d and fewer than %d", accepted, resolverQueueSize, resolverConcurrency+resolverQueueSize, fragmentCount)
	}
	releaseGateway()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for completed := range accepted {
		select {
		case <-fragmentsCompleted:
		case <-deadline.C:
			t.Fatalf("gateway finished %d of %d accepted DNS fragments", completed, accepted)
		}
	}
	observed := int(queryFragments.Load())
	t.Logf("resolver admitted %d fragments; gateway observed %d fragment queries, each declared %d; WriteTo error=%v", accepted, observed, declaredFragments.Load(), sendErr)
	fragmentMu.Lock()
	uniqueFragments := len(seenFragments)
	missingIndex := -1
	for index := range accepted {
		if _, ok := seenFragments[byte(index)]; !ok {
			missingIndex = index
			break
		}
	}
	fragmentMu.Unlock()
	if observed != accepted || uniqueFragments != accepted || int(declaredFragments.Load()) != fragmentCount {
		t.Fatalf("gateway queries=%d unique=%d declared=%d, want admitted=%d declared=%d", observed, uniqueFragments, declaredFragments.Load(), accepted, fragmentCount)
	}
	if missingIndex >= 0 {
		t.Fatalf("accepted fragment index %d did not reach gateway", missingIndex)
	}
	select {
	case got := <-received:
		t.Fatalf("incomplete %d-fragment uplink unexpectedly reassembled %d bytes", observed, len(got.data))
	default:
	}

	small := []byte("small-uplink")
	if n, err := client.WriteTo(small, nil); err != nil || n != len(small) {
		t.Fatalf("small recovery write = %d, %v", n, err)
	}
	select {
	case got := <-received:
		if got.err != nil || !bytes.Equal(got.data, small) {
			t.Fatalf("small recovery uplink = %q, %v", got.data, got.err)
		}
		if n, err := server.WriteTo([]byte("small-reply"), got.addr); err != nil || n != len("small-reply") {
			t.Fatalf("server reply WriteTo = %d, %v", n, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("small uplink did not recover after the 4096-byte attempt")
	}

	type readResult struct {
		data []byte
		err  error
	}
	clientRead := make(chan readResult, 1)
	go func() {
		reply := make([]byte, 64)
		n, _, err := client.ReadFrom(reply)
		clientRead <- readResult{data: reply[:n], err: err}
	}()
	select {
	case got := <-clientRead:
		if got.err != nil || !bytes.Equal(got.data, []byte("small-reply")) {
			t.Fatalf("downlink reply = %q, %v", got.data, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("small downlink response timed out")
	}
}
