package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/crypto"
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
	"golang.org/x/net/http2"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	sync.RWMutex
	ips           map[string]*record
	pub           *pubsub.Service
	cleanup       *task.Periodic
	httpClient    *http.Client
	dohURL        string
	name          string
	queryStrategy QueryStrategy
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
func NewDoHNameServer(url *url.URL, queryStrategy QueryStrategy, dispatcher routing.Dispatcher, h2c bool) *DoHNameServer {
	url.Scheme = "https"
	mode := "DOH"
	if dispatcher == nil {
		mode = "DOHL"
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", url.String(), ", with h2c ", h2c)
	s := &DoHNameServer{
		ips:           make(map[string]*record),
		pub:           pubsub.NewService(),
		name:          mode + "//" + url.Host,
		dohURL:        url.String(),
		queryStrategy: queryStrategy,
	}
	s.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.Cleanup,
	}
	s.httpClient = &http.Client{
		Transport: &http2.Transport{
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				var conn net.Conn
				if dispatcher != nil {
					dnsCtx := toDnsContext(ctx, s.dohURL)
					if h2c {
						dnsCtx = session.ContextWithMitmAlpn11(dnsCtx, false) // for insurance
						dnsCtx = session.ContextWithMitmServerName(dnsCtx, url.Hostname())
					}
					link, err := dispatcher.Dispatch(dnsCtx, dest)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					default:
					}
					if err != nil {
						return nil, err
					}
					cc := common.ChainedClosable{}
					if cw, ok := link.Writer.(common.Closable); ok {
						cc = append(cc, cw)
					}
					if cr, ok := link.Reader.(common.Closable); ok {
						cc = append(cc, cr)
					}
					conn = cnc.NewConnection(
						cnc.ConnectionInputMulti(link.Writer),
						cnc.ConnectionOutputMulti(link.Reader),
						cnc.ConnectionOnClose(cc),
					)
				} else {
					log.Record(&log.AccessMessage{
						From:   "DNS",
						To:     s.dohURL,
						Status: log.AccessAccepted,
						Detour: "local",
					})
					conn, err = internet.DialSystem(ctx, dest, nil)
					if err != nil {
						return nil, err
					}
				}
				if !h2c {
					conn = utls.UClient(conn, &utls.Config{ServerName: url.Hostname()}, utls.HelloChrome_Auto)
					if err := conn.(*utls.UConn).HandshakeContext(ctx); err != nil {
						return nil, err
					}
				}
				return conn, nil
			},
		},
	}
	return s
}

// Name implements Server.
func (s *DoHNameServer) Name() string {
	return s.name
}

// Cleanup clears expired items from cache
func (s *DoHNameServer) Cleanup() error {
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

func (s *DoHNameServer) updateIP(req *dnsRequest, ipRec *IPRecord) {
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
		addr := make([]net.Address, 0, len(ipRec.IP))
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

func (s *DoHNameServer) newReqID() uint16 {
	return 0
}

func (s *DoHNameServer) sendQuery(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.name, " querying: ", domain)

	if s.name+"." == "DOH//"+domain {
		errors.LogError(ctx, s.name, " tries to resolve itself! Use IP or set \"hosts\" instead.")
		return
	}

	// As we don't want our traffic pattern looks like DoH, we use Random-Length Padding instead of Block-Length Padding recommended in RFC 8467
	// Although DoH server like 1.1.1.1 will pad the response to Block-Length 468, at least it is better than no padding for response at all
	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(clientIP, int(crypto.RandBetween(100, 300))))

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
				Protocol:       "https",
				SkipDNSResolve: true,
			})

			// forced to use mux for DOH
			// dnsCtx = session.ContextWithMuxPreferred(dnsCtx, true)

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query for ", domain)
				return
			}
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to retrieve response for ", domain)
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle DOH response for ", domain)
				return
			}
			s.updateIP(r, rec)
		}(req)
	}
}

func (s *DoHNameServer) dohHTTPSContext(ctx context.Context, b []byte) ([]byte, error) {
	body := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", s.dohURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-message")
	req.Header.Add("Content-Type", "application/dns-message")

	req.Header.Set("X-Padding", strings.Repeat("X", int(crypto.RandBetween(100, 1000))))

	hc := s.httpClient

	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) // flush resp.Body so that the conn is reusable
		return nil, fmt.Errorf("DOH server returned code %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (s *DoHNameServer) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
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

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns_feature.IPOption, disableCache bool) ([]net.IP, uint32, error) { // nolint: dupl
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
