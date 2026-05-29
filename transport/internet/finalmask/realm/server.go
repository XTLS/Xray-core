package realm

import (
	"context"
	go_errors "errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

const (
	defaultEventBuffer       = 16
	defaultStunCacheTTL      = time.Second * 10
	defaultHeartbeatInterval = time.Second * 15
)

type PunchPacketEvent struct {
	Addr   netip.AddrPort
	Packet PunchPacket
}

type STUNPacketEvent struct {
	Message *stun.Message
	Addr    netip.AddrPort
}

type realmConnServer struct {
	cleaned chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	net.PacketConn

	realmClient   *Client
	realmID       string
	stunServers   []string
	stunTimeout   time.Duration
	punchTimeout  time.Duration
	punchInterval time.Duration

	events map[PunchMetadata]chan PunchPacketEvent
	stun   chan STUNPacketEvent
	mu     sync.Mutex

	locals     []netip.AddrPort
	localsMu   sync.Mutex
	localsLast time.Time
}

func NewConnServer(config *Config, raw net.PacketConn) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(context.Background())

	conn := &realmConnServer{
		cleaned:    make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		PacketConn: raw,

		realmClient:   NewClient(config.Scheme, config.Host, config.Port, config.Token, config.TlsConfig),
		realmID:       config.ID,
		stunServers:   config.StunServers,
		stunTimeout:   defaultSTUNTimeout,
		punchTimeout:  defaultPunchTimeout,
		punchInterval: defaultPunchInterval,

		events: make(map[PunchMetadata]chan PunchPacketEvent),
		stun:   make(chan STUNPacketEvent, defaultEventBuffer),
	}

	go conn.run()

	return conn, nil
}

func (c *realmConnServer) addSTUN(packet []byte) bool {
	if !stun.IsMessage(packet) {
		return false
	}
	msg, addr, err := parseSTUNBindingResponse(packet)
	if err != nil {
		return false
	}
	select {
	case c.stun <- STUNPacketEvent{Message: msg, Addr: addr}:
	default:
	}
	return true
}

func (c *realmConnServer) addPunch(packet []byte, addr net.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for meta, ch := range c.events {
		punchPacket, err := DecodePunchPacket(packet, meta)
		if err != nil {
			continue
		}
		select {
		case ch <- PunchPacketEvent{
			Addr:   addr.(*net.UDPAddr).AddrPort(),
			Packet: punchPacket,
		}:
		default:
		}
		return true
	}
	return false
}

func (c *realmConnServer) waitctx(ctx context.Context, t time.Duration) bool {
	timer := time.NewTimer(t)
	defer timer.Stop()
	select {
	case <-timer.C:
		return false
	case <-ctx.Done():
		return true
	}
}

func (c *realmConnServer) discover(servers []*net.UDPAddr) []netip.AddrPort {
	transactionIDs := make(map[[stun.TransactionIDSize]byte]struct{}, len(servers))
	for _, server := range servers {
		msg := common.Must2(stun.Build(stun.TransactionID, stun.BindingRequest))
		transactionIDs[msg.TransactionID] = struct{}{}
		_, _ = c.PacketConn.WriteTo(msg.Raw, server)
	}

	deadline := time.NewTimer(c.stunTimeout)
	results := make([]netip.AddrPort, 0, len(servers))
	for len(transactionIDs) > 0 {
		select {
		case <-deadline.C:
			goto end
		case ev := <-c.stun:
			if _, ok := transactionIDs[ev.Message.TransactionID]; ok {
				delete(transactionIDs, ev.Message.TransactionID)
				results = append(results, ev.Addr)
			}
		}
	}
end:
	deadline.Stop()
	slices.SortFunc(results, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})

	return results
}

func (c *realmConnServer) getlocals(force bool) []netip.AddrPort {
	c.localsMu.Lock()
	if force || time.Since(c.localsLast) > defaultStunCacheTTL {
		start := time.Now()
		servers := resolveSTUNServers(c.PacketConn.LocalAddr().(*net.UDPAddr).IP, c.stunServers)
		errors.LogDebug(context.Background(), "[realm] update stun servers ", servers, " with ", time.Since(start))
		if len(servers) > 0 {
			start = time.Now()
			locals := c.discover(servers)
			errors.LogDebug(context.Background(), "[realm] update stun locals ", locals, " with ", time.Since(start))
			if len(locals) > 0 {
				c.locals = locals
				c.localsLast = time.Now()
			}
		}
	}
	locals := append([]netip.AddrPort(nil), c.locals...)
	c.localsMu.Unlock()
	return locals
}

func (c *realmConnServer) punch(ctx context.Context, meta PunchMetadata, peers []netip.AddrPort) {
	c.mu.Lock()
	if _, ok := c.events[meta]; ok {
		c.mu.Unlock()
		return
	}
	ch := make(chan PunchPacketEvent, defaultEventBuffer)
	c.events[meta] = ch
	c.mu.Unlock()

	start := time.Now()
	for _, peer := range peers {
		packet := common.Must2(EncodePunchPacket(PunchPacketHello, meta))
		_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
	}
	deadline := time.NewTimer(c.punchTimeout)
	ticker := time.NewTicker(c.punchInterval)
	for {
		select {
		case <-ctx.Done():
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " FAIL > session end")
			goto end
		case <-deadline.C:
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " FAIL > timeout")
			goto end
		case <-ticker.C:
			for _, peer := range peers {
				packet := common.Must2(EncodePunchPacket(PunchPacketHello, meta))
				_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
			}
		case event := <-ch:
			if event.Packet.Type == PunchPacketHello {
				packet := common.Must2(EncodePunchPacket(PunchPacketAck, meta))
				_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(event.Addr))
			}
			errors.LogDebug(context.Background(), "[realm] punch ", meta.Nonce, " SUCCESS ", event.Addr, " with ", time.Since(start))
			goto end
		}
	}
end:
	deadline.Stop()
	ticker.Stop()

	c.mu.Lock()
	delete(c.events, meta)
	close(ch)
	c.mu.Unlock()
}

func (c *realmConnServer) run() {
	backoff := time.Second
retry:
	resp, err := c.realmClient.Register(c.ctx, c.realmID, addrPortStrings(c.getlocals(false)))
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[realm] ", c.realmID, " register session err retry in ", backoff)
		if c.waitctx(c.ctx, backoff) {
			close(c.cleaned)
			return
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		goto retry
	}
	backoff = time.Second
	errors.LogDebug(context.Background(), "[realm] ", c.realmID, " sesssion ", resp.SessionID, " ", resp.TTL, " registered")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 2)
	go c.heartbeatLoop(ctx, resp.SessionID, resp.TTL, errCh)
	go c.eventsLoop(ctx, resp.SessionID, resp.TTL, errCh)
	select {
	case <-c.ctx.Done():
	case err = <-errCh:
	}
	cancel()
	errors.LogDebugInner(context.Background(), err, "[realm] session ", resp.SessionID, " end")

	select {
	case <-c.ctx.Done():
		_ = c.realmClient.Deregister(context.Background(), c.realmID, resp.SessionID)
		errors.LogDebug(context.Background(), "[realm] ", c.realmID, " ", resp.SessionID, " deregistered")
		close(c.cleaned)
		return
	default:
		goto retry
	}
}

func (c *realmConnServer) heartbeatLoop(ctx context.Context, sid string, ttl int, errCh chan<- error) {
	interval := defaultHeartbeatInterval
	if ttl > 0 {
		interval = time.Second * time.Duration(ttl) / 2
	}

	last := time.Now()
	cur := c.getlocals(false)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			errCh <- nil
			return
		case <-ticker.C:
			req := HeartbeatRequest{}
			if new := c.getlocals(false); !slices.Equal(cur, new) {
				cur = new
				req.Addresses = addrPortStrings(cur)
			}
			start := time.Now()
			resp, err := c.realmClient.Heartbeat(ctx, c.realmID, sid, req)
			if err != nil {
				var statusErr *StatusError
				if go_errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound) {
					errCh <- errors.New("session invalid")
					return
				}
				if time.Since(last) > time.Second*time.Duration(ttl) {
					errCh <- errors.New("session lost")
					return
				}
				continue
			}
			last = start
			errors.LogDebug(context.Background(), "[realm] heartbeat ", resp.TTL, " with ", time.Since(start))
			if resp.TTL > 0 && resp.TTL != ttl {
				ttl = resp.TTL
				ticker.Reset(time.Second * time.Duration(ttl) / 2)
			}
		}
	}
}

func (c *realmConnServer) eventsLoop(ctx context.Context, sid string, ttl int, errCh chan<- error) {
	backoff := time.Second
	last := time.Now()
	for {
		start := time.Now()
		stream, err := c.realmClient.Events(ctx, c.realmID, sid)
		if err != nil {
			var statusErr *StatusError
			if go_errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound) {
				errCh <- errors.New("session invalid")
				return
			}
			if time.Since(last) > time.Second*time.Duration(ttl) {
				errCh <- errors.New("session lost")
				return
			}
			errors.LogDebugInner(context.Background(), err, "[realm] ", sid, " open stream err retry in ", backoff)
			if c.waitctx(ctx, backoff) {
				errCh <- nil
				return
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		last = start
		errors.LogDebug(context.Background(), "[realm] open stream with ", time.Since(start))
		for {
			ev, err := stream.Next()
			if err != nil {
				_ = stream.Close()
				break
			}
			last = time.Now()
			go c.punchEvent(ctx, sid, ev)
		}
	}
}

func (c *realmConnServer) punchEvent(ctx context.Context, sid string, ev *PunchEvent) {
	errors.LogDebug(context.Background(), "[realm] start punch event ", ev.Nonce, " ", ev.Addresses)

	locals := c.getlocals(false)

	peers, _ := parseAddrPorts(ev.Addresses)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " update peers ", peers)
	filteredPeers, seen := candidatePunchAddrs(locals, peers)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " filtered peers ", filteredPeers)
	expandedPeers := expandSymmetricNATCandidates(filteredPeers, seen)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " expanded peers ", expandedPeers)

	if len(expandedPeers) == 0 {
		errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " FAIL > empty peers")
		return
	}

	start := time.Now()
	err := c.realmClient.ConnectResponse(ctx, c.realmID, sid, ev.Nonce, addrPortStrings(locals))
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "[realm] ", ev.Nonce, " connect response err")
	}
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " connect response ", locals, " with ", time.Since(start))

	c.punch(ctx, ev.PunchMetadata, expandedPeers)
}

func (c *realmConnServer) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.addSTUN(p[:n]) {
			continue
		}
		if c.addPunch(p[:n], addr) {
			continue
		}
		return n, addr, nil
	}
}

func (c *realmConnServer) Close() error {
	c.cancel()
	<-c.cleaned
	return c.PacketConn.Close()
}
