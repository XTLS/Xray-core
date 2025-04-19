package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	go_errors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/http2"
)

// DoHNameServer implemented DNS over HTTPS (RFC8484) Wire Format,
// which is compatible with traditional dns over udp(RFC1035),
// thus most of the DOH implementation is copied from udpns.go
type DoHNameServer struct {
	cacheController *CacheController
	httpClient      *http.Client
	dohURL          string
	clientIP        net.IP
}

// NewDoHNameServer creates DOH/DOHL client object for remote/local resolving.
func NewDoHNameServer(url *url.URL, dispatcher routing.Dispatcher, h2c bool, disableCache bool, clientIP net.IP) *DoHNameServer {
	url.Scheme = "https"
	mode := "DOH"
	if dispatcher == nil {
		mode = "DOHL"
	}
	errors.LogInfo(context.Background(), "DNS: created ", mode, " client for ", url.String(), ", with h2c ", h2c)
	s := &DoHNameServer{
		cacheController: NewCacheController(mode+"//"+url.Host, disableCache),
		dohURL:          url.String(),
		clientIP:        clientIP,
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
	return s.cacheController.name
}

func (s *DoHNameServer) newReqID() uint16 {
	return 0
}

func (s *DoHNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, domain string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying: ", domain)

	if s.Name()+"." == "DOH//"+domain {
		errors.LogError(ctx, s.Name(), " tries to resolve itself! Use IP or set \"hosts\" instead.")
		noResponseErrCh <- errors.New("tries to resolve itself!", s.Name())
		return
	}

	// As we don't want our traffic pattern looks like DoH, we use Random-Length Padding instead of Block-Length Padding recommended in RFC 8467
	// Although DoH server like 1.1.1.1 will pad the response to Block-Length 468, at least it is better than no padding for response at all
	reqs := buildReqMsgs(domain, option, s.newReqID, genEDNS0Options(s.clientIP, int(crypto.RandBetween(100, 300))))

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
				noResponseErrCh <- err
				return
			}
			resp, err := s.dohHTTPSContext(dnsCtx, b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to retrieve response for ", domain)
				noResponseErrCh <- err
				return
			}
			rec, err := parseResponse(resp)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to handle DOH response for ", domain)
				noResponseErrCh <- err
				return
			}
			s.cacheController.updateIP(r, rec)
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

// QueryIP implements Server.
func (s *DoHNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) { // nolint: dupl
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
