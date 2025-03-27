package dns

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	sync.RWMutex
	name          string
	address       *net.Destination
	ips           map[string]*record
	requests      map[uint16]*udpDnsRequest
	pub           *pubsub.Service
	udpServer     *udp.Dispatcher
	cleanup       *task.Periodic
	reqID         uint32
	queryStrategy QueryStrategy
}

type udpDnsRequest struct {
	dnsRequest
	ctx context.Context
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, queryStrategy QueryStrategy) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(53)
	}

	s := &ClassicNameServer{
		address:       &address,
		ips:           make(map[string]*record),
		requests:      make(map[uint16]*udpDnsRequest),
		pub:           pubsub.NewService(),
		name:          strings.ToUpper(address.String()),
		queryStrategy: queryStrategy,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)
	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *ClassicNameServer) Cleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.ips) == 0 && len(s.requests) == 0 {
		return errors.New(s.name, " nothing to do. stopping...")
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

	for id, req := range s.requests {
		if req.expire.Before(now) {
			delete(s.requests, id)
		}
	}

	if len(s.requests) == 0 {
		s.requests = make(map[uint16]*udpDnsRequest)
	}

	return nil
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	ipRec, err := parseResponse(packet.Payload.Bytes())
	if err != nil {
		errors.LogError(ctx, s.name, " fail to parse responded DNS udp")
		return
	}

	s.Lock()
	id := ipRec.ReqID
	req, ok := s.requests[id]
	if ok {
		// remove the pending request
		delete(s.requests, id)
	}
	s.Unlock()
	if !ok {
		errors.LogError(ctx, s.name, " cannot find the pending request")
		return
	}

	// if truncated, retry with EDNS0 option(udp payload size: 1350)
	if ipRec.RawHeader.Truncated {
		// if already has EDNS0 option, no need to retry
		if ok && len(req.msg.Additionals) == 0 {
			// copy necessary meta data from original request
			// and add EDNS0 option
			opt := new(dnsmessage.Resource)
			common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
			opt.Body = &dnsmessage.OPTResource{}
			newMsg := *req.msg
			newReq := *req
			newMsg.Additionals = append(newMsg.Additionals, *opt)
			newMsg.ID = s.newReqID()
			newReq.msg = &newMsg
			s.addPendingRequest(&newReq)
			b, _ := dns.PackMessage(newReq.msg)
			s.udpServer.Dispatch(toDnsContext(newReq.ctx, s.address.String()), *s.address, b)
			return
		}
	}

	var rec record
	switch req.reqType {
	case dnsmessage.TypeA:
		rec.A = ipRec
	case dnsmessage.TypeAAAA:
		rec.AAAA = ipRec
	}

	elapsed := time.Since(req.start)
	errors.LogInfo(ctx, s.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed)
	if len(req.domain) > 0 && (rec.A != nil || rec.AAAA != nil) {
		s.updateIP(req.domain, &rec)
	}
}

func (s *ClassicNameServer) updateIP(domain string, newRec *record) {
	s.Lock()

	rec, found := s.ips[domain]
	if !found {
		rec = &record{}
	}

	updated := false
	if isNewer(rec.A, newRec.A) {
		rec.A = newRec.A
		updated = true
	}
	if isNewer(rec.AAAA, newRec.AAAA) {
		rec.AAAA = newRec.AAAA
		updated = true
	}

	if updated {
		errors.LogDebug(context.Background(), s.name, " updating IP records for domain:", domain)
		s.ips[domain] = rec
	}
	if newRec.A != nil {
		s.pub.Publish(domain+"4", nil)
	}
	if newRec.AAAA != nil {
		s.pub.Publish(domain+"6", nil)
	}
	s.Unlock()
	common.Must(s.cleanup.Start())
}

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) {
	s.Lock()
	defer s.Unlock()

	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
}

func (s *ClassicNameServer) sendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	errors.LogDebug(ctx, s.name, " querying DNS for: ", domain)

	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP, 0))

	for _, req := range reqs {
		udpReq := &udpDnsRequest{
			dnsRequest: *req,
			ctx:        ctx,
		}
		s.addPendingRequest(udpReq)
		b, _ := dns.PackMessage(req.msg)
		s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
	}
}

func (s *ClassicNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
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

	return nil, 0, dns_feature.ErrEmptyResponse
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, error) {
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
