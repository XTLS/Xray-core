package rawpacket

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"log"
	"math/big"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// masquerade answers probes that do not speak the tunnel protocol, so the
// relay port looks like a real service:
//
//	http/tls:  fake TCP handshake, then serve a static HTTP page or a
//	           TLS ServerHello + certificate flow
//	dns:       answer UDP queries with a DNS reply (A record for type A,
//	           NXDOMAIN otherwise), using the relay's own address
//
// Replies are sent from the address the probe dialed (dst of the
// incoming packet), never from the tunnel's spoofed source IPs.

type masqueradeMode int

const (
	masqOff masqueradeMode = iota
	masqHTTP
	masqTLS
	masqDNS

	masqFlowTTL     = 2 * time.Minute
	masqFlowCap     = 4096
	masqMaxChunkLen = 1400
)

func parseMasqueradeMode(s string) masqueradeMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "http":
		return masqHTTP
	case "tls", "https":
		return masqTLS
	case "dns":
		return masqDNS
	default:
		return masqOff
	}
}

func (m masqueradeMode) String() string {
	switch m {
	case masqHTTP:
		return "http"
	case masqTLS:
		return "tls"
	case masqDNS:
		return "dns"
	default:
		return "off"
	}
}

type masqKey struct {
	ip   netip.Addr
	port uint16
}

type fakeFlow struct {
	tcp      *TCPSimState
	resp     []byte
	sent     int
	lastSeen time.Time
}

type masquerade struct {
	mode   masqueradeMode
	fd     *rawSendFD
	relayP uint16 // relay listen port, source port of replies

	mu    sync.Mutex
	flows map[masqKey]*fakeFlow
	ipID  uint16
	idMu  sync.Mutex

	httpResp []byte
	tlsResp  []byte

	done chan struct{}
}

// newMasquerade builds the responder for mode; mode ""/"off" returns nil.
func newMasquerade(mode string, relayPort uint16) (*masquerade, error) {
	m := parseMasqueradeMode(mode)
	if m == masqOff {
		return nil, nil
	}
	fd, err := openRawSenderAny()
	if err != nil {
		return nil, err
	}
	resp, err := masqueradeResponses(m)
	if err != nil {
		fd.close()
		return nil, err
	}
	mg := &masquerade{
		mode:     m,
		fd:       fd,
		relayP:   relayPort,
		flows:    make(map[masqKey]*fakeFlow),
		httpResp: resp,
		tlsResp:  resp,
		done:     make(chan struct{}),
	}
	go mg.gcLoop()
	log.Printf("[rawpacket] masquerade enabled: %s (port %d)", m, relayPort)
	return mg, nil
}

// masqueradeResponses builds the static response payload for the mode.
func masqueradeResponses(m masqueradeMode) ([]byte, error) {
	switch m {
	case masqHTTP:
		return fakeHTTPResponse(), nil
	case masqTLS:
		return buildFakeTLSServer()
	default:
		return nil, nil
	}
}

func (m *masquerade) close() {
	if m == nil {
		return
	}
	close(m.done)
	m.fd.close()
}

func (m *masquerade) nextIPID() uint16 {
	m.idMu.Lock()
	defer m.idMu.Unlock()
	m.ipID++
	return m.ipID
}

// onTCPSYN handles a bare SYN from a probe: answer SYN|ACK and start a
// fake flow so subsequent data can be served.
func (m *masquerade) onTCPSYN(relayIP netip.Addr, relayPort uint16, probeIP netip.Addr, probePort uint16, seq uint32) {
	if m == nil || (m.mode != masqHTTP && m.mode != masqTLS) {
		return
	}
	key := masqKey{probeIP, probePort}
	m.mu.Lock()
	f := m.flows[key]
	if f == nil {
		resp := m.httpResp
		if m.mode == masqTLS {
			resp = m.tlsResp
		}
		f = &fakeFlow{tcp: newTCPSimState(), resp: resp}
		if len(m.flows) < masqFlowCap {
			m.flows[key] = f
		}
	}
	f.lastSeen = time.Now()
	f.tcp.observeClientSeq(seq, 0)
	m.mu.Unlock()
	m.sendTCP(relayIP, relayPort, probeIP, probePort, f, nil, true)
}

// onTCPData serves the fake response to probe data. The response is
// streamed in MSS-sized chunks and repeats once exhausted, so repeated
// requests (e.g. a browser reloading) keep getting answers.
func (m *masquerade) onTCPData(relayIP netip.Addr, relayPort uint16, probeIP netip.Addr, probePort uint16, seq uint32, payload []byte) {
	if m == nil || (m.mode != masqHTTP && m.mode != masqTLS) || len(payload) == 0 {
		return
	}
	key := masqKey{probeIP, probePort}
	m.mu.Lock()
	f := m.flows[key]
	if f == nil {
		m.mu.Unlock()
		return
	}
	f.lastSeen = time.Now()
	f.tcp.observeClientSeq(seq, len(payload))
	chunk := f.resp[f.sent:]
	if len(chunk) > masqMaxChunkLen {
		chunk = chunk[:masqMaxChunkLen]
	}
	f.sent += len(chunk)
	if f.sent >= len(f.resp) {
		f.sent = 0
	}
	m.mu.Unlock()
	m.sendTCP(relayIP, relayPort, probeIP, probePort, f, chunk, false)
}

func (m *masquerade) sendTCP(relayIP netip.Addr, relayPort uint16, probeIP netip.Addr, probePort uint16, f *fakeFlow, payload []byte, syn bool) {
	var flags uint8
	if syn {
		flags = TCPFlagSyn | TCPFlagAck
	} else {
		flags = TCPFlagAck
	}
	seq := f.tcp.nextSeq(len(payload))
	pkt := BuildTCPPacket(relayIP, probeIP, relayPort, probePort, seq, f.tcp.ack(), flags, payload, 64, m.nextIPID(), false)
	_ = m.fd.sendTo(pkt, probeIP)
}

// onUDP answers a probe datagram with a fake DNS reply.
func (m *masquerade) onUDP(relayIP netip.Addr, relayPort uint16, probeIP netip.Addr, probePort uint16, payload []byte) {
	if m == nil || m.mode != masqDNS || len(payload) < 12 {
		return
	}
	reply := fakeDNSReply(payload, relayIP)
	if len(reply) == 0 {
		return
	}
	pkt := BuildRawUDP(relayIP, probeIP, relayPort, probePort, reply, 64, m.nextIPID())
	_ = m.fd.sendTo(pkt, probeIP)
}

// gcLoop drops stale fake flows.
func (m *masquerade) gcLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			now := time.Now()
			m.mu.Lock()
			for k, f := range m.flows {
				if now.Sub(f.lastSeen) > masqFlowTTL {
					delete(m.flows, k)
				}
			}
			m.mu.Unlock()
		}
	}
}

// fakeHTTPResponse is a minimal nginx-style page.
func fakeHTTPResponse() []byte {
	body := "<html>\r\n<head><title>Welcome to nginx!</title></head>\r\n<body>\r\n<h1>Welcome to nginx!</h1>\r\n</body>\r\n</html>\r\n"
	hdr := "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n"
	return append([]byte(hdr), body...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// buildFakeTLSServer produces a canned TLS 1.2 ServerHello + Certificate +
// ServerHelloDone record flow backed by a self-signed ECDSA certificate.
// The handshake never completes (no key exchange), which is enough for
// passive DPI classification and port scanners.
func buildFakeTLSServer() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nginx", Organization: []string{"nginx"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	var random [32]byte
	_, _ = rand.Read(random[:])

	// ServerHello (TLS 1.2, ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	sh := make([]byte, 0, 38+32)
	sh = append(sh, 0x03, 0x03)
	sh = append(sh, random[:]...)
	sh = append(sh, 0x20)
	sh = append(sh, random[:32]...)
	sh = append(sh, 0xC0, 0x2B, 0x00)

	// handshake wrapper: type + 24-bit length
	hello := tlsHandshakeRecord(0x02, sh)

	// Certificate
	certMsg := make([]byte, 0, 3+len(der))
	certMsg = binary.BigEndian.AppendUint32(certMsg, uint32(len(der)))[1:]
	certMsg = append(certMsg, der...)
	cert := tlsHandshakeRecord(0x0B, certMsg)

	// ServerHelloDone
	done := tlsHandshakeRecord(0x0E, nil)

	var out []byte
	out = append(out, hello...)
	out = append(out, cert...)
	out = append(out, done...)
	return out, nil
}

// tlsHandshakeRecord wraps a handshake message in a TLS record (content
// type 0x16) with a 24-bit handshake length header.
func tlsHandshakeRecord(msgType byte, body []byte) []byte {
	out := make([]byte, 0, 5+4+len(body))
	out = append(out, 0x16, 0x03, 0x03)
	l := 4 + len(body)
	out = append(out, byte(l>>8), byte(l))
	out = append(out, msgType)
	out = append(out, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	out = append(out, body...)
	return out
}

// fakeDNSReply builds a DNS reply for query: an A record with the relay's
// address for type A queries, NXDOMAIN otherwise. Malformed queries yield
// nil (no reply). The question is always echoed.
func fakeDNSReply(query []byte, relayIP netip.Addr) []byte {
	if len(query) < 12 {
		return nil
	}
	id := query[0:2]
	flags := binary.BigEndian.Uint16(query[2:4])
	qd := binary.BigEndian.Uint16(query[4:6])
	if qd == 0 {
		return nil
	}
	off := 12
	qnameEnd := -1
	for off < len(query) {
		l := int(query[off])
		if l == 0 {
			off++
			qnameEnd = off
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer: name ends at 2-byte pointer
			off += 2
			qnameEnd = off
			break
		}
		if off+1+l > len(query) {
			return nil
		}
		off += 1 + l
		if off-12 > 255 {
			return nil
		}
	}
	if qnameEnd < 0 || off+4 > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[off:])
	qclass := binary.BigEndian.Uint16(query[off+2:])

	// QR=1, opcode echoed, RD echoed, RA=1; rcode 3 (NXDOMAIN) unless we
	// answer the query.
	rcode := uint16(3)
	ancount := uint16(0)
	var answer []byte
	if qtype == 1 && qclass == 1 && relayIP.Is4() { // A query
		rcode = 0
		ancount = 1
		answer = make([]byte, 0, 16)
		answer = append(answer, 0xC0, 0x0C)                // name pointer to question
		answer = binary.BigEndian.AppendUint16(answer, 1)  // type A
		answer = binary.BigEndian.AppendUint16(answer, 1)  // class IN
		answer = binary.BigEndian.AppendUint32(answer, 60) // TTL
		answer = binary.BigEndian.AppendUint16(answer, 4)  // rdlength
		answer = append(answer, relayIP.AsSlice()...)
	}

	reply := make([]byte, 0, len(query)+16)
	reply = append(reply, id...)
	reply = binary.BigEndian.AppendUint16(reply, 0x8000|(flags&0x7800)|0x0080|rcode)
	reply = binary.BigEndian.AppendUint16(reply, 1) // QDCOUNT
	reply = binary.BigEndian.AppendUint16(reply, ancount)
	reply = binary.BigEndian.AppendUint16(reply, 0) // NS
	reply = binary.BigEndian.AppendUint16(reply, 0) // AR
	reply = append(reply, query[12:off+4]...)       // question: qname + type + class
	reply = append(reply, answer...)
	return reply
}
