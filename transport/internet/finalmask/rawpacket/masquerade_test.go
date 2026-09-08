package rawpacket

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseMasqueradeMode(t *testing.T) {
	cases := map[string]masqueradeMode{
		"":      masqOff,
		"off":   masqOff,
		"http":  masqHTTP,
		"tls":   masqTLS,
		"https": masqTLS,
		"dns":   masqDNS,
		"HTTP":  masqHTTP,
	}
	for in, want := range cases {
		if got := parseMasqueradeMode(in); got != want {
			t.Fatalf("parseMasqueradeMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFakeHTTPResponse(t *testing.T) {
	resp := fakeHTTPResponse()
	if len(resp) == 0 {
		t.Fatal("empty HTTP response")
	}
	s := string(resp)
	if !startsWith(s, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("missing status line: %q", s[:32])
	}
	// Content-Length must match the body length
	body := "<html>\r\n<head><title>Welcome to nginx!</title></head>\r\n<body>\r\n<h1>Welcome to nginx!</h1>\r\n</body>\r\n</html>\r\n"
	cl := "Content-Length: " + itoa(len(body))
	if !contains(s, cl) {
		t.Fatalf("missing %q in %q", cl, s[:120])
	}
}

func TestBuildFakeTLSServer(t *testing.T) {
	resp, err := buildFakeTLSServer()
	if err != nil {
		t.Fatal(err)
	}
	// Expect 3 TLS records: ServerHello, Certificate, ServerHelloDone
	var off int
	var types []byte
	var lens []int
	for off < len(resp) && len(types) < 3 {
		if off+5 > len(resp) || resp[off] != 0x16 {
			t.Fatalf("bad record header at %d: %x", off, resp[off:])
		}
		l := int(resp[off+3])<<8 | int(resp[off+4])
		if off+5+l > len(resp) {
			t.Fatalf("record overruns buffer at %d", off)
		}
		types = append(types, resp[off+5])
		lens = append(lens, l)
		off += 5 + l
	}
	if off != len(resp) {
		t.Fatalf("trailing bytes after 3 records: %d", len(resp)-off)
	}
	if types[0] != 0x02 || types[1] != 0x0B || types[2] != 0x0E {
		t.Fatalf("record types = %x, want [2 b e]", types)
	}
	// Certificate record must contain a DER cert
	if lens[1] < 4 {
		t.Fatalf("certificate record too small: %d", lens[1])
	}
}

func TestFakeDNSReplyA(t *testing.T) {
	// build a DNS A query for example.com
	q := buildDNSQuery("example.com", 1, 0x1234, 0x0100)
	relay := netip.MustParseAddr("203.0.113.9")
	reply := fakeDNSReply(q, relay)
	if reply == nil {
		t.Fatal("nil reply for A query")
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Fatalf("bad ID")
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&0x8000 == 0 {
		t.Fatal("QR not set")
	}
	if flags&0x000F != 0 {
		t.Fatalf("rcode = %d, want 0 for A query", flags&0x000F)
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", binary.BigEndian.Uint16(reply[4:6]))
	}
	if an := binary.BigEndian.Uint16(reply[6:8]); an != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", an)
	}
	// answer: pointer to name + A record with relay IP
	a := reply[len(reply)-4:]
	if a[0] != 203 || a[3] != 9 {
		t.Fatalf("answer = %v, want relay IP", a)
	}
	if rdlen := binary.BigEndian.Uint16(reply[len(reply)-6 : len(reply)-4]); rdlen != 4 {
		t.Fatalf("rdlength = %d, want 4", rdlen)
	}
}

func TestFakeDNSReplyNXDOMAIN(t *testing.T) {
	q := buildDNSQuery("host.example", 28, 0xABCD, 0x0100) // AAAA query
	relay := netip.MustParseAddr("203.0.113.9")
	reply := fakeDNSReply(q, relay)
	if reply == nil {
		t.Fatal("nil reply")
	}
	if flags := binary.BigEndian.Uint16(reply[2:4]); flags&0x000F != 3 {
		t.Fatalf("rcode = %d, want 3 (NXDOMAIN)", flags&0x000F)
	}
	if an := binary.BigEndian.Uint16(reply[6:8]); an != 0 {
		t.Fatalf("ANCOUNT = %d, want 0", an)
	}
}

func TestFakeDNSReplyMalformed(t *testing.T) {
	relay := netip.MustParseAddr("203.0.113.9")
	if fakeDNSReply([]byte("short"), relay) != nil {
		t.Fatal("short query should be dropped")
	}
	// QDCOUNT = 0
	q := make([]byte, 12)
	if fakeDNSReply(q, relay) != nil {
		t.Fatal("zero-question query should be dropped")
	}
	// truncated name
	q = buildDNSQuery("example.com", 1, 0x1, 0x0100)
	if fakeDNSReply(q[:len(q)-4], relay) != nil {
		t.Fatal("truncated query should be dropped")
	}
}

func TestMasqueradeFlowLifecycle(t *testing.T) {
	// build directly to avoid opening a raw socket (needs privileges)
	rec := &recordingFD{}
	m := &masquerade{
		mode:     masqHTTP,
		fd:       rec.fd(),
		relayP:   443,
		flows:    make(map[masqKey]*fakeFlow),
		httpResp: fakeHTTPResponse(),
		done:     make(chan struct{}),
	}
	defer close(m.done)

	probe := netip.MustParseAddr("198.51.100.7")
	relay := netip.MustParseAddr("203.0.113.9")

	// bare SYN
	m.onTCPSYN(relay, 443, probe, 50000, 1000)
	if len(rec.pkts) != 1 {
		t.Fatalf("SYN should produce 1 packet, got %d", len(rec.pkts))
	}
	synack := rec.pkts[0]
	if synack[33] != TCPFlagSyn|TCPFlagAck {
		t.Fatalf("flags = %#x, want SYN|ACK", synack[33])
	}
	if ack := binary.BigEndian.Uint32(synack[28:32]); ack != 1001 {
		t.Fatalf("ack = %d, want 1001", ack)
	}
	if binary.BigEndian.Uint16(synack[20:22]) != 443 {
		t.Fatalf("src port = %d, want 443", binary.BigEndian.Uint16(synack[20:22]))
	}

	// data (HTTP GET) -> response chunk
	rec.pkts = nil
	m.onTCPData(relay, 443, probe, 50000, 1001, []byte("GET / HTTP/1.1\r\n\r\n"))
	if len(rec.pkts) != 1 {
		t.Fatalf("data should produce 1 packet, got %d", len(rec.pkts))
	}
	data := rec.pkts[0]
	payload := data[52:] // 20 ip + 32 tcp (20 hdr + 12 options)
	if !startsWith(string(payload), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected payload: %q", payload[:min(len(payload), 40)])
	}
	if seq := binary.BigEndian.Uint32(data[24:28]); seq == 0 {
		t.Fatal("seq should be relay ISN, got 0")
	}

	// unknown flow data -> no reply
	rec.pkts = nil
	m.onTCPData(relay, 443, netip.MustParseAddr("198.51.100.8"), 51000, 1, []byte("x"))
	if len(rec.pkts) != 0 {
		t.Fatalf("unknown flow should not get a reply")
	}
}

func TestMasqueradeDNSFlow(t *testing.T) {
	rec := &recordingFD{}
	m := &masquerade{
		mode:   masqDNS,
		fd:     rec.fd(),
		relayP: 53,
		flows:  make(map[masqKey]*fakeFlow),
		done:   make(chan struct{}),
	}
	defer close(m.done)

	probe := netip.MustParseAddr("198.51.100.7")
	relay := netip.MustParseAddr("203.0.113.9")
	q := buildDNSQuery("example.com", 1, 0x4242, 0x0100)
	m.onUDP(relay, 53, probe, 40000, q)
	if len(rec.pkts) != 1 {
		t.Fatalf("dns probe should get 1 reply, got %d", len(rec.pkts))
	}
	pkt := rec.pkts[0]
	if pkt[9] != 17 {
		t.Fatalf("protocol = %d, want UDP", pkt[9])
	}
	if binary.BigEndian.Uint16(pkt[22:24]) != 40000 {
		t.Fatalf("dst port = %d, want 40000", binary.BigEndian.Uint16(pkt[22:24]))
	}
	udpPayload := pkt[28:]
	// DNS reply parses
	if len(udpPayload) < 12 || binary.BigEndian.Uint16(udpPayload[0:2]) != 0x4242 {
		t.Fatalf("bad DNS reply in packet")
	}

	// non-DNS garbage -> no reply
	rec.pkts = nil
	m.onUDP(relay, 53, probe, 40000, []byte("garbage"))
	if len(rec.pkts) != 0 {
		t.Fatalf("garbage should not get a DNS reply")
	}
}

func TestMasqueradeOff(t *testing.T) {
	m, err := newMasquerade("", 443)
	if err != nil || m != nil {
		t.Fatalf("off mode should return nil, nil; got %v, %v", m, err)
	}
	m, err = newMasquerade("off", 443)
	if err != nil || m != nil {
		t.Fatalf("off mode should return nil, nil; got %v, %v", m, err)
	}
}

// --- helpers ---

type recordingFD struct {
	pkts [][]byte
}

func (r *recordingFD) fd() *rawSendFD {
	rf := &rawSendFD{}
	rf.sendFn = func(pkt []byte, _ netip.Addr) error {
		r.pkts = append(r.pkts, append([]byte(nil), pkt...))
		return nil
	}
	return rf
}

func buildDNSQuery(name string, qtype uint16, id uint16, flags uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], flags)
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, part := range stringsSplit(name, ".") {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	return q
}

func stringsSplit(s, sep string) []string {
	var out []string
	start := 0
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			out = append(out, s[start:i])
			start = i + len(sep)
		}
	}
	out = append(out, s[start:])
	return out
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
