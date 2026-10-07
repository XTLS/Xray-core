package xdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	resolverTimeout       = 10 * time.Second
	resolverMaxConcurrent = 16
	resolverMaxResponse   = 4096
)

type encryptedTransport interface {
	Exchange(context.Context, []byte) ([]byte, error)
	Close()
}

// encryptedResolver adapts request/response transports to XDNS's asynchronous
// Resolver interface without blocking the client's resolver scheduler.
type encryptedResolver struct {
	transport encryptedTransport
	addr      *net.UDPAddr
	ctx       context.Context
	cancel    context.CancelFunc
	readCh    chan []byte
	sem       chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
}

func newEncryptedResolver(transport encryptedTransport, dest xnet.Destination) *encryptedResolver {
	ctx, cancel := context.WithCancel(context.Background())
	ip := net.IPv4zero
	if dest.Address.Family().IsIP() {
		ip = append(net.IP(nil), dest.Address.IP()...)
	}
	return &encryptedResolver{
		transport: transport,
		addr:      &net.UDPAddr{IP: ip, Port: int(dest.Port)},
		ctx:       ctx,
		cancel:    cancel,
		readCh:    make(chan []byte, resolverMaxConcurrent),
		sem:       make(chan struct{}, resolverMaxConcurrent),
	}
}

func (r *encryptedResolver) Addr() *net.UDPAddr { return r.addr }

func (r *encryptedResolver) Read(p []byte) (int, error) {
	response, ok := <-r.readCh
	if !ok {
		return 0, io.ErrClosedPipe
	}
	return copy(p, response), nil
}

func (r *encryptedResolver) Send(p []byte) {
	if len(p) < 12 || len(p) > resolverMaxResponse {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	select {
	case r.sem <- struct{}{}:
	default:
		return
	}
	query := append([]byte(nil), p...)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.sem }()
		ctx, cancel := context.WithTimeout(r.ctx, resolverTimeout)
		defer cancel()
		response, err := r.transport.Exchange(ctx, query)
		if err != nil {
			xerrors.LogDebug(r.ctx, "xdns encrypted resolver: ", err)
			return
		}
		if len(response) > resolverMaxResponse || !matchesDNSQuestion(query, response) || binary.BigEndian.Uint16(query[:2]) != binary.BigEndian.Uint16(response[:2]) {
			return
		}
		select {
		case r.readCh <- response:
		case <-ctx.Done():
		}
	}()
}

func (r *encryptedResolver) Close() {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		r.mu.Unlock()
		r.transport.Close()
		r.wg.Wait()
		r.transport.Close()
		close(r.readCh)
	})
}

func dialResolverTCP(ctx context.Context, dialer *finalmask.Dialer, dest xnet.Destination) (net.Conn, error) {
	if dialer == nil {
		return nil, errors.New("resolver TCP dialer is unavailable")
	}
	if dialer.DialTCPContext != nil {
		return dialer.DialTCPContext(ctx, dest)
	}
	if dialer.DialTCP == nil {
		return nil, errors.New("resolver TCP dialer is unavailable")
	}
	return dialer.DialTCP(dest)
}

func matchesDNSQuestion(query, response []byte) bool {
	var q, r dnsmessage.Message
	if q.Unpack(query) != nil || r.Unpack(response) != nil || !r.Response || len(q.Questions) != 1 || len(r.Questions) != 1 {
		return false
	}
	return q.Questions[0].Type == r.Questions[0].Type && q.Questions[0].Class == r.Questions[0].Class && strings.EqualFold(q.Questions[0].Name.String(), r.Questions[0].Name.String())
}
