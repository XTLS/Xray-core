package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// TCPNameServer implemented DNS over TCP (RFC7766).
type TCPNameServer struct {
	cacheController *CacheController
	destination     *net.Destination
	reqID           uint32
	dial            func(context.Context) (net.Conn, error)
	clientIP        net.IP
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
	dispatcher routing.Dispatcher,
	disableCache bool,
	clientIP net.IP,
) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCP", disableCache, clientIP)
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		link, err := dispatcher.Dispatch(toDnsContext(ctx, s.destination.String()), *s.destination)
		if err != nil {
			return nil, err
		}

		return cnc.NewConnection(
			cnc.ConnectionInputMulti(link.Writer),
			cnc.ConnectionOutputMulti(link.Reader),
		), nil
	}

	return s, nil
}

// NewTCPLocalNameServer creates DNS over TCP client object for local resolving
func NewTCPLocalNameServer(url *url.URL, disableCache bool, clientIP net.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCPL", disableCache, clientIP)
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, *s.destination, nil)
	}

	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string, disableCache bool, clientIP net.IP) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	s := &TCPNameServer{
		cacheController: NewCacheController(prefix+"//"+dest.NetAddr(), disableCache),
		destination:     &dest,
		clientIP:        clientIP,
	}

	return s, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.cacheController.name
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, domain string, option dns_feature.IPOption) {
	errors.LogDebug(ctx, s.Name(), " querying DNS for: ", domain)

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(s.clientIP, 0))

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			dnsCtx := ctx

			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "dns",
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

			conn, err := s.dial(dnsCtx)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to dial namesever")
				noResponseErrCh <- err
				return
			}
			defer conn.Close()
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

			_, err = conn.Write(dnsReqBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				noResponseErrCh <- err
				return
			}
			dnsReqBuf.Release()

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
				errors.LogErrorInner(ctx, err, "failed to parse DNS over TCP response")
				noResponseErrCh <- err
				return
			}

			s.cacheController.updateIP(r, rec)
		}(req)
	}
}

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
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
