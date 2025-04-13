package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
)

// TCPNameServer implemented DNS over TCP (RFC7766).
type TCPNameServer struct {
	sync.RWMutex
	name        string
	destination *net.Destination
	ips         map[string]*record
	pub         *pubsub.Service
	cleanup     *task.Periodic
	reqID       uint32
	dial        func(context.Context) (net.Conn, error)
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
	dispatcher routing.Dispatcher,
) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCP")
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
func NewTCPLocalNameServer(url *url.URL) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCPL")
	if err != nil {
		return nil, err
	}

	s.dial = func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, *s.destination, nil)
	}

	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	s := &TCPNameServer{
		destination: &dest,
		ips:         make(map[string]*record),
		pub:         pubsub.NewService(),
		name:        prefix + "//" + dest.NetAddr(),
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}

	return s, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *TCPNameServer) Cleanup() error {
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

func (s *TCPNameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	s.Lock()
	rec, found := s.ips[req.domain]
	if !found {
		rec = &record{}
	}

	switch req.reqType {
	case dnsmessage.TypeA:
		rec.A = ipRec
	case dnsmessage.TypeAAAA:
		ips := make([]net.IP, 0, len(ipRec.IP))
		for _, ip := range ipRec.IP {
			if len(ip) == net.IPv6len {
				ips = append(ips, ip)
			}
		}
		ipRec.IP = ips
		rec.AAAA = ipRec
	}

	errors.LogInfo(context.Background(), s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed)
	s.ips[req.domain] = rec

	switch req.reqType {
	case dnsmessage.TypeA:
		s.pub.Publish(req.domain+"4", nil)
	case dnsmessage.TypeAAAA:
		s.pub.Publish(req.domain+"6", nil)
	}

	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, domain string, clientIP net.IP, option dns_feature.IPOption) {
	errors.LogDebug(ctx, s.name, " querying DNS for: ", domain)

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP, 0))

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

			s.updateIP(r, rec)
		}(req)
	}
}

func (s *TCPNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	s.RLock()
	record, found := s.ips[domain]
	s.RUnlock()

	if !found {
		return nil, 0, errRecordNotFound
	}

	var errs []error
	var allIPs []net.IP
	var rTTL uint32 = dns_feature.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := record.A.getIPs()
		if !mergeReq || err == errRecordNotFound {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if option.IPv6Enable {
		ips, ttl, err := record.AAAA.getIPs()
		if !mergeReq || err == errRecordNotFound {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if len(allIPs) > 0 {
		return allIPs, rTTL, nil
	}
	if go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	if disableCache {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", domain, " at ", s.name)
	} else {
		ips, ttl, err := s.findIPsForDomain(fqdn, option)
		if err != errRecordNotFound {
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
				return
			}
		}
		if sub6 != nil {
			select {
			case <-sub6.Wait():
			case <-ctx.Done():
				return
			}
		}
		close(done)
	}()
	noResponseErrCh := make(chan error, 2)
	s.sendQuery(ctx, noResponseErrCh, fqdn, clientIP, option)
	start := time.Now()

	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case err := <-noResponseErrCh:
		return nil, 0, err
	case <-done:
		ips, ttl, err := s.findIPsForDomain(fqdn, option)
		log.Record(&log.DNSLog{Server: s.name, Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
		return ips, ttl, err
	}
}
