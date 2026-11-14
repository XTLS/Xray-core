package dns

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	requestsCleanup *task.Periodic
	reqID           uint32
	clientIP        net.IP
}

type udpDnsRequest struct {
	dnsRequest
	ctx context.Context
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	if address.Port == 0 {
		address.Port = net.Port(53)
	}
	s := newClassicNameServer(address, strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL, clientIP)
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)
	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

// NewUDPLocalNameServer creates a UDP client that bypasses the Xray dispatcher.
func NewUDPLocalNameServer(u *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*ClassicNameServer, error) {
	if u.Hostname() == "" {
		return nil, errors.New("missing UDP local nameserver host")
	}
	port := net.Port(53)
	if u.Port() != "" {
		var err error
		if port, err = net.PortFromString(u.Port()); err != nil {
			return nil, err
		}
	}
	address := net.UDPDestination(net.ParseAddress(u.Hostname()), port)
	s := newClassicNameServer(address, "UDPL//"+address.NetAddr(), disableCache, serveStale, serveExpiredTTL, clientIP)
	errors.LogInfo(context.Background(), "DNS: created Local UDP client initialized for ", u.String())
	return s, nil
}

func newClassicNameServer(address net.Destination, name string, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	s := &ClassicNameServer{
		cacheController: NewCacheController(name, disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		requests:        make(map[uint16]*udpDnsRequest),
		clientIP:        clientIP,
	}
	s.requestsCleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.RequestsCleanup,
	}
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *ClassicNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// RequestsCleanup clears expired items from cache
func (s *ClassicNameServer) RequestsCleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.requests) == 0 {
		return errors.New(s.Name(), " nothing to do. stopping...")
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

// dispatch sends through the router for classic UDP, or directly for local UDP.
func (s *ClassicNameServer) dispatch(ctx context.Context, payload *buf.Buffer) {
	if s.udpServer != nil {
		s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, payload)
		return
	}
	go s.dispatchLocal(ctx, payload)
}

func (s *ClassicNameServer) dispatchLocal(ctx context.Context, payload *buf.Buffer) {
	defer payload.Release()
	conn, err := internet.DialSystem(ctx, *s.address, nil)
	if err != nil {
		if ctx.Err() == nil {
			errors.LogInfoInner(ctx, err, s.Name(), " failed to dial local UDP nameserver")
		}
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			errors.LogInfoInner(ctx, err, s.Name(), " failed to set UDP deadline")
			return
		}
	}
	if _, err := conn.Write(payload.Bytes()); err != nil {
		if ctx.Err() == nil {
			errors.LogInfoInner(ctx, err, s.Name(), " failed to send local UDP query")
		}
		return
	}
	response := buf.New()
	if _, err := response.ReadFrom(conn); err != nil {
		response.Release()
		if ctx.Err() == nil {
			errors.LogInfoInner(ctx, err, s.Name(), " failed to read local UDP response")
		}
		return
	}
	s.HandleResponse(ctx, &udp_proto.Packet{Payload: response, Source: *s.address})
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	payload := packet.Payload
	ipRec, err := parseResponse(payload.Bytes())
	payload.Release()
	if err != nil {
		errors.LogErrorInner(ctx, err, s.Name(), " fail to parse responded DNS udp")
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
		errors.LogErrorInner(ctx, err, s.Name(), " cannot find the pending request")
		return
	}

	// if truncated, retry with EDNS0 option(udp payload size: 1350)
	if ipRec.RawHeader.Truncated {
		// if already has EDNS0 option, no need to retry
		if len(req.msg.Additionals) == 0 {
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
			s.dispatch(newReq.ctx, b)
			return
		}
	}

	s.cacheController.updateRecord(&req.dnsRequest, ipRec)
}

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) {
	s.Lock()
	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
}

// getCacheController implements CachedNameserver.
func (s *ClassicNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *ClassicNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	for _, req := range reqs {
		udpReq := &udpDnsRequest{
			dnsRequest: *req,
			ctx:        ctx,
		}
		s.addPendingRequest(udpReq)
		b, err := dns.PackMessage(req.msg)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to pack dns query")
			if noResponseErrCh != nil {
				noResponseErrCh <- err
			}
			return
		}
		s.dispatch(ctx, b)
	}
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
