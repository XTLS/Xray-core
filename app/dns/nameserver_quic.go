package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq"

const handshakeTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	ips           map[string]*record
	pub           *pubsub.Service
	cleanup       *task.Periodic
	name          string
	destination   *net.Destination
	connection    quic.Connection
	queryStrategy QueryStrategy
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL, queryStrategy QueryStrategy) (*QUICNameServer, error) {
	errors.LogInfo(context.Background(), "DNS: created Local DNS-over-QUIC client for ", url.String())

	var err error
	port := net.Port(853)
	if url.Port() != "" {
		port, err = net.PortFromString(url.Port())
		if err != nil {
			return nil, err
		}
	}
	dest := net.UDPDestination(net.ParseAddress(url.Hostname()), port)

	s := &QUICNameServer{
		ips:           make(map[string]*record),
		pub:           pubsub.NewService(),
		name:          url.String(),
		destination:   &dest,
		queryStrategy: queryStrategy,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}

	return s, nil
}

// Name returns client name
func (s *QUICNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *QUICNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 {
		return errors.New("nothing to do. stopping...")
	}

	for domain, record := range s.ips {
		if record.A != nil && record.A.Expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.Expire.Before(now) {
			record.AAAA = nil
		}

		if record.A == nil && record.AAAA == nil {
			errors.LogDebug(context.Background(), s.name, " cleanup ", domain)
			delete(s.ips, domain)
		} else {
			s.ips[domain] = record
		}
	}

	if len(s.ips) == 0 {
		s.ips = make(map[string]*record)
	}

	return nil
}

func (s *QUICNameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	s.Lock()
	rec, found := s.ips[req.domain]
	if !found {
		rec = &record{}
	}
	updated := false

	switch req.reqType {
	case dnsmessage.TypeA:
		if isNewer(rec.A, ipRec) {
			rec.A = ipRec
			updated = true
		}
	case dnsmessage.TypeAAAA:
		addr := make([]net.Address, 0)
		for _, ip := range ipRec.IP {
			if len(ip.IP()) == net.IPv6len {
				addr = append(addr, ip)
			}
		}
		ipRec.IP = addr
		if isNewer(rec.AAAA, ipRec) {
			rec.AAAA = ipRec
			updated = true
		}
	}
	errors.LogInfo(context.Background(), s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed)

	if updated {
		s.ips[req.domain] = rec
	}
	switch req.reqType {
	case dnsmessage.TypeA:
		s.pub.Publish(req.domain+"4", nil)
	case dnsmessage.TypeAAAA:
		s.pub.Publish(req.domain+"6", nil)
	}
	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *QUICNameServer) newReqID() uint16 {
	return 0
}

func (s *QUICNameServer) sendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.name, " querying: ", domain)

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP, 0))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			// generate new context for each req, using same context
			// may cause reqs all aborted if any one encounter an error
			dnsCtx := ctx

			// reserve internal dns server requested Inbound
			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "quic",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query")
				return
			}

			dnsReqBuf := buf.New()
			binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			dnsReqBuf.Write(b.Bytes())
			b.Release()

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to open quic connection")
				return
			}

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				return
			}
			var length int16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse response length")
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle response")
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *QUICNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	s.RLock()
	record, found := s.ips[domain]
	s.RUnlock()

	if !found {
		return nil, 0, errRecordNotFound
	}

	var err4 error
	var err6 error
	var ips []net.Address
	var ip6 []net.Address
	var ttl uint32

	if option.IPv4Enable {
		ips, ttl, err4 = record.A.getIPs()
	}

	if option.IPv6Enable {
		ip6, ttl, err6 = record.AAAA.getIPs()
		ips = append(ips, ip6...)
	}

	if len(ips) > 0 {
		netips, err := toNetIP(ips)
		return netips, ttl, err
	}

	if err4 != nil {
		return nil, 0, err4
	}

	if err6 != nil {
		return nil, 0, err6
	}

	if (option.IPv4Enable && record.A != nil) || (option.IPv6Enable && record.AAAA != nil) {
		return nil, 0, dns_feature.ErrEmptyResponse
	}

	return nil, 0, errRecordNotFound
}

// QueryIP is called from dns.Server->queryIPTimeout
func (s *QUICNameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)
	option = ResolveIpOptionOverride(s.queryStrategy, option)
	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns_feature.ErrEmptyResponse
	}

	if disableCache {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", domain, " at ", s.name)
	} else {
		ips, ttl, err := s.findIPsForDomain(fqdn, option)
		if err == nil || err == dns_feature.ErrEmptyResponse || dns_feature.RCodeFromError(err) == 3 {
			errors.LogDebugInner(ctx, err, s.name, " cache HIT ", domain, " -> ", ips)
			log.Record(&log.DNSLog{Server: s.name, Domain: domain, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
			return ips, ttl, err
		}
	}

	// ipv4 and ipv6 belong to different subscription groups
	var sub4, sub6 *pubsub.Subscriber
	if option.IPv4Enable {
		sub4 = s.pub.Subscribe(fqdn + "4")
		defer sub4.Close()
	}
	if option.IPv6Enable {
		sub6 = s.pub.Subscribe(fqdn + "6")
		defer sub6.Close()
	}
	done := make(chan interface{})
	go func() {
		if sub4 != nil {
			select {
			case <-sub4.Wait():
			case <-ctx.Done():
			}
		}
		if sub6 != nil {
			select {
			case <-sub6.Wait():
			case <-ctx.Done():
			}
		}
		close(done)
	}()
	s.sendQuery(ctx, fqdn, clientIP, option)
	start := time.Now()

	for {
		ips, ttl, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
			log.Record(&log.DNSLog{Server: s.name, Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
			return ips, ttl, err
		}

		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-done:
		}
	}
}

func isActive(s quic.Connection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection() (quic.Connection, error) {
	var conn quic.Connection
	s.RLock()
	conn = s.connection
	if conn != nil && isActive(conn) {
		s.RUnlock()
		return conn, nil
	}
	if conn != nil {
		// we're recreating the connection, let's create a new one
		_ = conn.CloseWithError(0, "")
	}
	s.RUnlock()

	s.Lock()
	defer s.Unlock()

	var err error
	conn, err = s.openConnection()
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC connection.
		conn, err = s.openConnection()
		if err != nil {
			return nil, err
		}
	}
	s.connection = conn
	return conn, nil
}

func (s *QUICNameServer) openConnection() (quic.Connection, error) {
	tlsConfig := tls.Config{}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
	}
	tlsConfig.ServerName = s.destination.Address.String()
	conn, err := quic.DialAddr(context.Background(), s.destination.NetAddr(), tlsConfig.GetTLSConfig(tls.WithNextProto("http/1.1", http2.NextProtoTLS, NextProtoDQ)), quicConfig)
	log.Record(&log.AccessMessage{
		From:   "DNS",
		To:     s.destination,
		Status: log.AccessAccepted,
		Detour: "local",
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (s *QUICNameServer) openStream(ctx context.Context) (quic.Stream, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}
