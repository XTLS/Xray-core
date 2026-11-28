package dns

import (
	"context"
	"io"
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
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
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
	requestsCleanup *task.Periodic
	reqID           uint32
	clientIP        net.IP

	dispatcher routing.Dispatcher
	local      bool
	exchangeMu sync.Mutex
	exchange   *dnsUDPExchange
}

type udpDnsRequest struct {
	dnsRequest
	ctx context.Context
}

// dnsUDPExchange carries queries for one nameserver while its transport lives.
// Local mode sends straight to its socket. Routed mode supplies pending queries
// and the response parser as the endpoints of the selected outbound.
type dnsUDPExchange struct {
	ctx    context.Context
	cancel context.CancelFunc
	timer  *signal.ActivityTimer
	conn   net.Conn
	inbox  *udp.PacketInbox
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(53)
	}

	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		requests:        make(map[uint16]*udpDnsRequest),
		clientIP:        clientIP,
		dispatcher:      dispatcher,
	}
	s.requestsCleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.RequestsCleanup,
	}
	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

// NewUDPNameServer creates a UDP DNS client from a URL.
func NewUDPNameServer(url *url.URL, dispatcher routing.Dispatcher, local bool, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*ClassicNameServer, error) {
	if url.Hostname() == "" {
		return nil, errors.New("missing UDP nameserver host")
	}
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	s := NewClassicNameServer(net.UDPDestination(net.ParseAddress(url.Hostname()), port), dispatcher, disableCache, serveStale, serveExpiredTTL, clientIP)
	if local {
		s.local = true
		s.cacheController.name = "UDPL//" + s.address.NetAddr()
	}
	return s, nil
}

func (s *ClassicNameServer) getExchange(ctx context.Context) (*dnsUDPExchange, error) {
	s.exchangeMu.Lock()
	defer s.exchangeMu.Unlock()
	if s.exchange != nil && s.exchange.ctx.Err() == nil {
		return s.exchange, nil
	}

	ctx, cancel := context.WithCancel(udp.WithPacketRouteState(toDnsContext(ctx, s.address.String())))
	exchange := &dnsUDPExchange{ctx: ctx, cancel: cancel}
	if s.local {
		conn, err := internet.DialSystem(ctx, *s.address, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		exchange.conn = conn
	} else {
		if s.dispatcher == nil {
			cancel()
			return nil, errors.New("routing dispatcher is required for UDP DNS")
		}
		exchange.inbox = udp.NewPacketInbox(policy.BufferPolicyFromContext(ctx).PerConnection)
		exchange.inbox.AttachRoute(ctx)
	}
	exchange.timer = signal.CancelAfterInactivity(ctx, cancel, time.Minute)
	s.exchange = exchange
	context.AfterFunc(ctx, func() {
		exchange.timer.SetTimeout(0)
		if exchange.conn != nil {
			exchange.conn.Close()
		} else {
			exchange.inbox.Close()
		}
		s.exchangeMu.Lock()
		if s.exchange == exchange {
			s.exchange = nil
		}
		s.exchangeMu.Unlock()
	})

	response := &dnsUDPResponseWriter{server: s, exchange: exchange}
	if exchange.conn != nil {
		go func() {
			defer cancel()
			reader := buf.NewPacketReader(exchange.conn)
			for {
				packets, err := reader.ReadMultiBuffer()
				if err != nil {
					buf.ReleaseMulti(packets)
					if ctx.Err() == nil {
						errors.LogInfoInner(ctx, err, "failed to read local UDP DNS response")
					}
					return
				}
				if err := response.WriteMultiBuffer(packets); err != nil {
					return
				}
			}
		}()
	} else {
		go func() {
			defer cancel()
			reader := udp.NewDispatchPacketReader(ctx, cancel, exchange.inbox, nil)
			link := &transport.Link{Reader: reader, Writer: response}
			if err := s.dispatcher.DispatchLink(ctx, *s.address, link); err != nil && ctx.Err() == nil {
				errors.LogInfoInner(ctx, err, "failed to dispatch UDP DNS")
			}
		}()
	}
	return exchange, nil
}

func (s *ClassicNameServer) sendPacket(req *udpDnsRequest, packet *buf.Buffer) {
	ctx := req.ctx
	if ctx.Err() != nil {
		packet.Release()
		return
	}
	exchange, err := s.getExchange(ctx)
	if err != nil {
		packet.Release()
		errors.LogInfoInner(ctx, err, "failed to open UDP DNS exchange")
		return
	}
	s.addPendingRequest(req)
	if exchange.conn != nil {
		if err = ctx.Err(); err == nil {
			if _, err = exchange.conn.Write(packet.Bytes()); err != nil {
				exchange.cancel()
			}
		}
		packet.Release()
	} else {
		// Admission belongs to this query's work deadline. The nameserver's
		// exchange and its already-admitted queries can outlive it.
		err = exchange.inbox.Put(ctx, buf.MultiBuffer{packet})
	}
	if err != nil {
		s.Lock()
		if id := req.msg.ID; s.requests[id] == req {
			delete(s.requests, id)
		}
		s.Unlock()
		if ctx.Err() == nil {
			errors.LogInfoInner(ctx, err, "failed to send UDP DNS query")
		}
	}
}

type dnsUDPResponseWriter struct {
	server   *ClassicNameServer
	exchange *dnsUDPExchange
}

func (w *dnsUDPResponseWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	ctx := w.exchange.ctx
	if ctx.Err() != nil {
		buf.ReleaseMulti(packets)
		return io.ErrClosedPipe
	}
	w.exchange.timer.Update()
	for _, packet := range packets {
		source := *w.server.address
		if packet.UDP != nil {
			source = *packet.UDP
		}
		w.server.HandleResponse(ctx, &udp_proto.Packet{Payload: packet, Source: source})
	}
	return nil
}

func (w *dnsUDPResponseWriter) Interrupt() { w.exchange.cancel() }

func (w *dnsUDPResponseWriter) Close() error {
	w.Interrupt()
	return nil
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
			b, err := dns.PackMessage(newReq.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack DNS UDP retry")
				return
			}
			// A retry can wait for outbound admission. Do not make the
			// response writer (including a shared Mux reader) wait for it.
			go s.sendPacket(&newReq, b)
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
		b, err := dns.PackMessage(req.msg)
		if err != nil {
			errors.LogErrorInner(ctx, err, "failed to pack dns query")
			if noResponseErrCh != nil {
				noResponseErrCh <- err
			}
			return
		}
		s.sendPacket(udpReq, b)
	}
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
