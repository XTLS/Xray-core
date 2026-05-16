package realm

import (
	"context"
	go_errors "errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

const defaultEventBuffer = 16
const defaultStunCacheTTL = time.Second * 10
const defaultHeartbeatInterval = time.Second * 15

type PunchPacketEvent struct {
	Addr   netip.AddrPort
	Packet PunchPacket
}

type PunchPacketEventWithMeta struct {
	Meta PunchMetadata
	Ch   chan PunchPacketEvent
}

type STUNPacketEvent struct {
	Message *stun.Message
	Addr    netip.AddrPort
}

type PunchPacketConn struct {
	cleaned chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	rClient *Client
	config  *internet.RealmConfig
	net.PacketConn

	events map[string]*PunchPacketEventWithMeta
	stun   chan STUNPacketEvent
	mu     sync.Mutex

	locals     []netip.AddrPort
	localsMu   sync.Mutex
	localsLast time.Time
}

func NewPunchPacketConn(config *internet.RealmConfig, raw net.PacketConn) (*PunchPacketConn, error) {
	start := time.Now()
	servers := resolveSTUNServers(raw.LocalAddr().(*net.UDPAddr).IP, config.StunServers)
	errors.LogDebug(context.Background(), "[realm] get stun servers ", servers, " with ", time.Since(start))
	if len(servers) == 0 {
		return nil, errors.New("empty stun servers")
	}

	start = time.Now()
	locals := Discover(raw, servers)
	errors.LogDebug(context.Background(), "[realm] get stun locals ", locals, " with ", time.Since(start))
	if len(locals) == 0 {
		return nil, errors.New("empty stun locals")
	}

	rClient, err := NewClient(config.Scheme, config.Host, config.Port, config.Token)
	if err != nil {
		return nil, errors.New("http create").Base(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := &PunchPacketConn{
		cleaned:    make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		rClient:    rClient,
		config:     config,
		PacketConn: raw,

		events: make(map[string]*PunchPacketEventWithMeta),
		stun:   make(chan STUNPacketEvent, defaultEventBuffer),

		locals:     locals,
		localsLast: time.Now(),
	}

	go conn.run()

	return conn, nil
}

func (c *PunchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *PunchPacketConn) Close() error {
	c.cancel()
	<-c.cleaned
	return c.PacketConn.Close()
}

func (c *PunchPacketConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.PacketConn.(syscall.Conn)
	if !ok {
		return nil, go_errors.ErrUnsupported
	}
	return sc.SyscallConn()
}

func (c *PunchPacketConn) addSTUN(packet []byte) bool {
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

func (c *PunchPacketConn) addPunch(packet []byte, addr net.Addr) bool {
	var added bool
	c.mu.Lock()
	for _, ev := range c.events {
		punchPacket, err := DecodePunchPacket(packet, ev.Meta)
		if err != nil {
			continue
		}
		select {
		case ev.Ch <- PunchPacketEvent{
			Addr:   addr.(*net.UDPAddr).AddrPort(),
			Packet: punchPacket,
		}:
		default:
		}
		added = true
		break
	}
	c.mu.Unlock()
	return added
}

func (c *PunchPacketConn) run() {
	backoff := time.Second
retry:
	resp, err := c.rClient.Register(c.ctx, c.config.ID, addrPortStrings(c.getlocals(false)))
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[realm] failed to register session for ", c.config.ID, " retry in ", backoff)
		if waitctx(c.ctx, backoff) {
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
	errors.LogDebug(context.Background(), "[realm] ", c.config.ID, " sesssion ", resp.SessionID, " ", resp.TTL, " registered")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 2)
	go c.heartbeatLoop(ctx, resp.SessionID, resp.TTL, errCh)
	go c.eventsLoop(ctx, resp.SessionID, resp.TTL, errCh)
	select {
	case <-c.ctx.Done():
	case err = <-errCh:
	}
	cancel()
	errors.LogDebug(context.Background(), "[realm] session ", resp.SessionID, " end with err ", err)

	select {
	case <-c.ctx.Done():
		_ = c.rClient.Deregister(context.Background(), c.config.ID, resp.SessionID)
		errors.LogDebug(context.Background(), "[realm] ", c.config.ID, " ", resp.SessionID, " deregistered")
		close(c.cleaned)
		return
	default:
		goto retry
	}
}

func (c *PunchPacketConn) heartbeatLoop(ctx context.Context, sid string, ttl int, errCh chan<- error) {
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
			resp, err := c.rClient.Heartbeat(ctx, c.config.ID, sid, req)
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

func (c *PunchPacketConn) eventsLoop(ctx context.Context, sid string, ttl int, errCh chan<- error) {
	backoff := time.Second
	last := time.Now()
	for {
		start := time.Now()
		stream, err := c.rClient.Events(ctx, c.config.ID, sid)
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
			errors.LogDebug(context.Background(), "[realm] ", sid, " open stream err ", err, " retry in ", backoff)
			if waitctx(ctx, backoff) {
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
			go c.punch(ctx, sid, ev, defaultPunchTimeout, defaultPunchInterval)
		}
	}
}

func (c *PunchPacketConn) punch(ctx context.Context, sid string, ev *PunchEvent, timeout, interval time.Duration) {
	errors.LogDebug(context.Background(), "[realm] start punch event ", ev.Nonce, " ", ev.Addresses)

	locals := c.getlocals(false)

	peers, _ := parseAddrPorts(ev.Addresses)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " get peers ", peers)
	filteredPeers, seen := candidatePunchAddrs(locals, peers)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " filtered peers ", filteredPeers)
	expandedPeers := expandSymmetricNATCandidates(filteredPeers, seen)
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " expanded peers ", expandedPeers)

	if len(expandedPeers) == 0 {
		errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " FAIL > empty peers")
		return
	}

	start := time.Now()
	_ = c.rClient.ConnectResponse(ctx, c.config.ID, sid, ev.Nonce, addrPortStrings(locals))
	errors.LogDebug(context.Background(), "[realm] ", ev.Nonce, " connect response ", locals, " with ", time.Since(start))

	c.mu.Lock()
	if _, ok := c.events[ev.Nonce]; ok {
		c.mu.Unlock()
		return
	}
	ch := make(chan PunchPacketEvent, defaultEventBuffer)
	c.events[ev.Nonce] = &PunchPacketEventWithMeta{Meta: ev.PunchMetadata, Ch: ch}
	c.mu.Unlock()

	start = time.Now()
	sendPunchPackets(c, expandedPeers, ev.PunchMetadata, PunchPacketHello)
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " FAIL > session end")
			goto end
		case <-deadline.C:
			errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " FAIL > timeout")
			goto end
		case <-ticker.C:
			sendPunchPackets(c, expandedPeers, ev.PunchMetadata, PunchPacketHello)
		case event := <-ch:
			if event.Packet.Type == PunchPacketHello {
				sendPunchPacket(c, event.Addr, ev.PunchMetadata, PunchPacketAck)
			}
			errors.LogDebug(context.Background(), "[realm] punch ", ev.Nonce, " SUCCESS ", event.Addr, " with ", time.Since(start))
			goto end
		}
	}
end:
	deadline.Stop()
	ticker.Stop()

	c.mu.Lock()
	delete(c.events, ev.Nonce)
	close(ch)
	c.mu.Unlock()
}

func (c *PunchPacketConn) getlocals(force bool) []netip.AddrPort {
	c.localsMu.Lock()
	if force || time.Since(c.localsLast) > defaultStunCacheTTL {
		start := time.Now()
		servers := resolveSTUNServers(c.LocalAddr().(*net.UDPAddr).IP, c.config.StunServers)
		errors.LogDebug(context.Background(), "[realm] get stun servers ", servers, " with ", time.Since(start))
		if len(servers) > 0 {
			start = time.Now()
			locals := DiscoverWithDemux(c.WriteTo, c.stun, servers)
			errors.LogDebug(context.Background(), "[realm] get stun locals ", locals, " with ", time.Since(start))
			if len(locals) > 0 {
				c.locals = locals
			}
		}
	}
	locals := append([]netip.AddrPort(nil), c.locals...)
	c.localsMu.Unlock()
	return locals
}

func waitctx(ctx context.Context, t time.Duration) bool {
	timer := time.NewTimer(t)
	defer timer.Stop()
	select {
	case <-timer.C:
		return false
	case <-ctx.Done():
		return true
	}
}
