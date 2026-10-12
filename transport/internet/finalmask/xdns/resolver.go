package xdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// shortcut: DNS wire messages are limited to 4096 bytes; expand the client decode boundary before raising this limit.
	maxDNSMessageSize      = 4096
	resolverRequestTimeout = 5 * time.Second
	resolverConcurrency    = 16
	resolverQueueSize      = 64
)

type Resolver interface {
	Addr() *net.UDPAddr
	Read(p []byte) (int, error)
	// Send accepts a copy of one DNS message; success does not promise remote delivery.
	Send(p []byte) error
	Close()
}

func NewResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	if config == nil || dialer == nil {
		return nil, errors.New("missing resolver configuration or dialer")
	}
	switch config.Type {
	case "tcp":
		return NewTCPResolver(config, dialer)
	case "udp":
		return NewUDPResolver(config, dialer)
	case "tls":
		return NewDoTResolver(config, dialer)
	case "https":
		return NewDoHResolver(config, dialer)
	case "quic":
		return NewDoQResolver(config, dialer)
	case "https+h3":
		return NewDoH3Resolver(config, dialer)
	default:
		return nil, errors.New("unknown type")
	}
}

type resolverRequest struct {
	message  []byte
	deadline time.Time
}

type requestResolver struct {
	ctx            context.Context
	cancel         context.CancelFunc
	addr           *net.UDPAddr
	requests       chan resolverRequest
	responses      chan []byte
	wg             sync.WaitGroup
	mu             sync.Mutex
	once           sync.Once
	closeTransport func()
}

func newRequestResolver(addr *net.UDPAddr, exchange func(context.Context, []byte) ([]byte, error), closeTransport func()) *requestResolver {
	ctx, cancel := context.WithCancel(context.Background())
	r := &requestResolver{ctx: ctx, cancel: cancel, addr: addr, requests: make(chan resolverRequest, resolverQueueSize), responses: make(chan []byte, resolverQueueSize), closeTransport: closeTransport}
	for range resolverConcurrency {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case request := <-r.requests:
					requestCtx, stop := context.WithDeadline(ctx, request.deadline)
					var response []byte
					var err error
					if err = requestCtx.Err(); err == nil {
						response, err = exchange(requestCtx, request.message)
						if err == nil {
							err = validateDNSResponse(request.message, response)
						}
					}
					if err != nil {
						if ctx.Err() == nil {
							xerrors.LogWarningInner(ctx, err, "xdns resolver request failed")
						}
						stop()
						continue
					}
					select {
					case r.responses <- response:
					case <-requestCtx.Done():
					}
					stop()
				}
			}
		}()
	}
	return r
}

func (r *requestResolver) Addr() *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), r.addr.IP...), Port: r.addr.Port, Zone: r.addr.Zone}
}

func (r *requestResolver) Send(p []byte) error {
	if err := validateDNSQuery(p); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return io.ErrClosedPipe
	}
	request := resolverRequest{message: append([]byte(nil), p...), deadline: time.Now().Add(resolverRequestTimeout)}
	select {
	case r.requests <- request:
		return nil
	default:
		return errors.New("xdns resolver request queue is full")
	}
}

func (r *requestResolver) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	select {
	case <-r.ctx.Done():
		return 0, io.ErrClosedPipe
	case packet := <-r.responses:
		if len(p) < len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}

func (r *requestResolver) Close() {
	r.once.Do(func() {
		r.mu.Lock()
		r.cancel()
		r.mu.Unlock()
		if r.closeTransport != nil {
			r.closeTransport()
		}
		r.wg.Wait()
	})
}

func validateDNSQuery(p []byte) error {
	if len(p) < 12 || len(p) > maxDNSMessageSize {
		return errors.New("invalid DNS message length")
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(p); err != nil {
		return err
	}
	if msg.Response || msg.OpCode != 0 || len(msg.Questions) != 1 {
		return errors.New("expected one DNS question")
	}
	return nil
}

func validateDNSResponse(query, response []byte) error {
	if len(response) < 12 || len(response) > maxDNSMessageSize {
		return errors.New("invalid DNS response length")
	}
	var request, reply dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		return err
	}
	if err := reply.Unpack(response); err != nil {
		return err
	}
	if !reply.Response || reply.ID != request.ID || reply.OpCode != request.OpCode || len(request.Questions) != 1 || len(reply.Questions) != 1 {
		return errors.New("DNS response does not match request")
	}
	q, a := request.Questions[0], reply.Questions[0]
	if q.Type != a.Type || q.Class != a.Class || !strings.EqualFold(q.Name.String(), a.Name.String()) {
		return errors.New("DNS response question does not match request")
	}
	return nil
}

func resolverTarget(hostPort, bootstrap string, network xnet.Network) (xnet.Destination, *net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return xnet.Destination{}, nil, err
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n/@?#") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return xnet.Destination{}, nil, errors.New("invalid resolver hostname")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return xnet.Destination{}, nil, errors.New("invalid resolver port")
	}
	identity := net.ParseIP(host)
	if bootstrap != "" {
		identity = net.ParseIP(bootstrap)
		if identity == nil {
			return xnet.Destination{}, nil, errors.New("bootstrap must be a single IP address")
		}
		host = bootstrap
	}
	if identity == nil {
		identity = net.IPv4zero
	}
	return xnet.Destination{Network: network, Address: xnet.ParseAddress(host), Port: xnet.Port(p)}, &net.UDPAddr{IP: append(net.IP(nil), identity...), Port: int(p)}, nil
}

func resolverTLSConfig(config *ResolverProto, serverName string, nextProtos ...string) (*tls.Config, error) {
	if serverName == "" || strings.ContainsAny(serverName, " \t\r\n/@?#") {
		return nil, errors.New("invalid TLS server name")
	}
	for _, certificate := range config.Certificates {
		if certificate == nil || certificate.Usage != xtls.Certificate_AUTHORITY_VERIFY || !x509.NewCertPool().AppendCertsFromPEM(certificate.Certificate) {
			return nil, errors.New("resolver certificates must contain valid verify roots")
		}
	}
	tlsConfig := (&xtls.Config{Certificate: config.Certificates}).GetTLSConfig()
	tlsConfig.ServerName = serverName
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = append([]string(nil), nextProtos...)
	if tlsConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("resolver TLS verification must remain enabled")
	}
	return tlsConfig, nil
}
