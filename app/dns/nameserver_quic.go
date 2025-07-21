package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq"

const handshakeTimeout = time.Second * 8

// QUICNameServer implemented DNS over QUIC
type QUICNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	destination     *net.Destination
	connection      *quic.Conn
	clientIP        net.IP
}

// NewQUICNameServer creates DNS-over-QUIC client object for local resolving
func NewQUICNameServer(url *url.URL, disableCache bool, clientIP net.IP) (*QUICNameServer, error) {
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
		cacheController: NewCacheController(url.String(), disableCache),
		destination:     &dest,
		clientIP:        clientIP,
	}

	return s, nil
}

// Name returns client name
func (s *QUICNameServer) Name() string {
	return s.cacheController.name
}

func (s *QUICNameServer) newReqID() uint16 {
	return 0
}

func (s *QUICNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, domain string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", domain)

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(s.clientIP, 0))

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
				noResponseErrCh <- err
				return
			}

			dnsReqBuf := buf.New()
			err = binary.Write(dnsReqBuf, binary.BigEndian, uint16(b.Len()))
			if err != nil {
				errors.LogErrorInner(ctx, err, "binary write failed")
				noResponseErrCh <- err
				return
			}
			_, err = dnsReqBuf.Write(b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "buffer write failed")
				noResponseErrCh <- err
				return
			}
			b.Release()

			conn, err := s.openStream(dnsCtx)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to open quic connection")
				noResponseErrCh <- err
				return
			}

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				noResponseErrCh <- err
				return
			}

			_ = conn.Close()

			respBuf := buf.New()
			defer respBuf.Release()
			n, err := respBuf.ReadFullFrom(conn, 2)
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				noResponseErrCh <- err
				return
			}
			var length int16
			err = binary.Read(bytes.NewReader(respBuf.Bytes()), binary.BigEndian, &length)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse response length")
				noResponseErrCh <- err
				return
			}
			respBuf.Clear()
			n, err = respBuf.ReadFullFrom(conn, int32(length))
			if err != nil && n == 0 {
				errors.LogErrorInner(ctx, err, "failed to read response length")
				noResponseErrCh <- err
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle response")
				noResponseErrCh <- err
				return
			}
			s.cacheController.updateIP(r, rec)
		}(req)
	}
}

// QueryIP is called from dns.Server->queryIPTimeout
func (s *QUICNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)
	sub4, sub6 := s.cacheController.registerSubscribers(fqdn, option)
	defer closeSubscribers(sub4, sub6)

	if s.cacheController.disableCache {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", domain, " at ", s.Name())
	} else {
		ips, ttl, err := s.cacheController.findIPsForDomain(fqdn, option)
		if !go_errors.Is(err, errRecordNotFound) {
			errors.LogDebugInner(ctx, err, s.Name(), " cache HIT ", domain, " -> ", ips)
			log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
			return ips, ttl, err
		}
	}

	noResponseErrCh := make(chan error, 2)
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)
	start := time.Now()

	if sub4 != nil {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case err := <-noResponseErrCh:
			return nil, 0, err
		case <-sub4.Wait():
			sub4.Close()
		}
	}
	if sub6 != nil {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case err := <-noResponseErrCh:
			return nil, 0, err
		case <-sub6.Wait():
			sub6.Close()
		}
	}

	ips, ttl, err := s.cacheController.findIPsForDomain(fqdn, option)
	log.Record(&log.DNSLog{Server: s.Name(), Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	return ips, ttl, err

}

func isActive(s *quic.Conn) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

func (s *QUICNameServer) getConnection() (*quic.Conn, error) {
	var conn *quic.Conn
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

func (s *QUICNameServer) openConnection() (*quic.Conn, error) {
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

func (s *QUICNameServer) openStream(ctx context.Context) (*quic.Stream, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, err
	}

	// open a new stream
	return conn.OpenStreamSync(ctx)
}
