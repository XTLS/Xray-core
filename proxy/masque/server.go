package masque

import (
	"context"
	go_errors "errors"
	"io"
	stdnet "net"
	"net/http"
	"net/netip"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/wireguard"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/masque"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	authenticateHeader = `Basic realm="masque", charset="UTF-8"`
	tunnelQueueSize    = 512
)

type Server struct {
	validator  *validator
	dispatcher routing.Dispatcher
	ctx        context.Context
	tag        string
	sniffing   session.SniffingRequest
	mtu        int

	dev   tun.Device
	pools []*addressPool
	local []netip.Addr

	mu      sync.RWMutex
	tunnels map[netip.Addr]*serverTunnel
	closed  bool
	started bool
}

type serverTunnel struct {
	conn   stat.Connection
	ipConn *connectip.Conn
	user   *protocol.MemoryUser
	addrs  []netip.Addr
	queue  chan *buf.Buffer
	done   chan struct{}

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newServerTunnel(conn stat.Connection, user *protocol.MemoryUser) *serverTunnel {
	return &serverTunnel{
		conn:  conn,
		user:  user,
		queue: make(chan *buf.Buffer, tunnelQueueSize),
		done:  make(chan struct{}),
		conns: make(map[net.Conn]struct{}),
	}
}

func (t *serverTunnel) send(b *buf.Buffer) bool {
	select {
	case <-t.done:
		return false
	default:
	}
	select {
	case t.queue <- b:
		return true
	default:
		return false
	}
}

func (t *serverTunnel) track(conn net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns == nil {
		return false
	}
	t.conns[conn] = struct{}{}
	return true
}

func (t *serverTunnel) untrack(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

func (t *serverTunnel) close() {
	t.mu.Lock()
	conns := t.conns
	if conns != nil {
		t.conns = nil
		close(t.done)
	}
	t.mu.Unlock()
	for conn := range conns {
		conn.Close()
	}
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*masque.Config); !ok {
		return nil, errors.New("not masque transport")
	}
	if tls.ConfigFromStreamSettings(streamSettings) == nil {
		return nil, errors.New(`MASQUE requires "security": "tls"`)
	}

	users := newValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get MASQUE user").Base(err)
		}
		if err := users.add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err)
		}
	}

	var pools []*addressPool
	var local []netip.Addr
	for _, s := range config.Address {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, errors.New("invalid address ", s).Base(err)
		}
		if slices.ContainsFunc(local, func(addr netip.Addr) bool { return addr.Is4() == prefix.Addr().Is4() }) {
			return nil, errors.New("only one address per IP family is supported")
		}
		pool, err := newAddressPool(prefix)
		if err != nil {
			return nil, err
		}
		pools = append(pools, pool)
		local = append(local, prefix.Addr())
	}
	if len(pools) == 0 {
		return nil, errors.New("no address to assign")
	}

	mtu := int(config.Mtu)
	if mtu == 0 {
		mtu = masque.MinPacketSize
	}
	dev, _, gstack, err := wireguard.CreateNetTUN(local, nil, mtu, false)
	if err != nil {
		return nil, err
	}

	s := &Server{
		validator:  users,
		dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:        core.ToBackgroundDetachedContext(ctx),
		mtu:        mtu,
		dev:        dev,
		pools:      pools,
		local:      local,
		tunnels:    make(map[netip.Addr]*serverTunnel),
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		s.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		s.sniffing = content.SniffingRequest
	}
	wireguard.CreateForwarder(gstack, s.handleConnection)
	return s, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return nil
	}
	s.started = true
	go s.readFromStack()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var tunnels []*serverTunnel
	for _, t := range s.tunnels {
		if !slices.Contains(tunnels, t) {
			tunnels = append(tunnels, t)
		}
	}
	s.mu.Unlock()
	for _, t := range tunnels {
		t.conn.Close()
	}
	return s.dev.Close()
}

func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return s.validator.add(user)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	user, err := s.validator.delByEmail(email)
	if err != nil {
		return err
	}
	s.mu.RLock()
	var conns []stat.Connection
	for _, t := range s.tunnels {
		if t.user == user && !slices.Contains(conns, t.conn) {
			conns = append(conns, t.conn)
		}
	}
	s.mu.RUnlock()
	for _, conn := range conns {
		conn.Close()
	}
	return nil
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.getByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.getAll()
}

func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.count()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sconn, ok := stat.TryUnwrapStatsConn(conn).(*masque.ServerConn)
	if !ok {
		return errors.New("not a MASQUE connection")
	}
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "masque"
	inbound.CanSpliceCopy = 3

	name, pass, _ := sconn.Request().BasicAuth()
	user := s.validator.get(name, pass)
	if user == nil {
		sconn.Reject(http.StatusUnauthorized, http.Header{"WWW-Authenticate": {authenticateHeader}})
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: errors.New("invalid credentials"),
		})
		return errors.New("MASQUE: authentication failed for ", name)
	}
	inbound.User = user

	t := newServerTunnel(conn, user)
	for _, pool := range s.pools {
		if addr, ok := pool.allocate(); ok {
			t.addrs = append(t.addrs, addr)
		}
	}
	defer s.release(t)
	if len(t.addrs) == 0 {
		sconn.Reject(http.StatusServiceUnavailable, nil)
		return errors.New("MASQUE: no address left to assign")
	}

	ipConn, err := sconn.Accept()
	if err != nil {
		return errors.New("MASQUE: failed to accept the tunnel").Base(err)
	}
	t.ipConn = ipConn
	if !s.register(t) {
		return errors.New("MASQUE: server closed")
	}
	if !s.validator.contains(user) {
		return errors.New("MASQUE: user ", name, " was removed")
	}
	go s.writeToTunnel(t)

	prefixes := make([]netip.Prefix, len(t.addrs))
	for i, addr := range t.addrs {
		prefixes[i] = netip.PrefixFrom(addr, addr.BitLen())
	}
	if err := ipConn.AssignAddresses(prefixes); err != nil {
		return err
	}
	if err := ipConn.AdvertiseRoute(fullRoutes(t.addrs)); err != nil {
		return err
	}
	go serveAddressRequests(t)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     "",
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "MASQUE: tunnel from ", inbound.Source, " assigned ", t.addrs)
	return s.readFromTunnel(t)
}

func fullRoutes(addrs []netip.Addr) []connectip.IPRoute {
	var routes []connectip.IPRoute
	if slices.ContainsFunc(addrs, netip.Addr.Is4) {
		routes = append(routes, connectip.IPRoute{StartIP: netip.IPv4Unspecified(), EndIP: netip.AddrFrom4([4]byte{255, 255, 255, 255})})
	}
	if slices.ContainsFunc(addrs, netip.Addr.Is6) {
		routes = append(routes, connectip.IPRoute{StartIP: netip.IPv6Unspecified(), EndIP: netip.AddrFrom16([16]byte{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})})
	}
	return routes
}

func serveAddressRequests(t *serverTunnel) {
	for {
		req, err := t.ipConn.ReceiveAddressRequest(context.Background())
		if err != nil {
			return
		}
		assigned := make([]netip.Prefix, len(req.Prefixes))
		used := make(map[netip.Addr]bool)
		for i, requested := range req.Prefixes {
			for _, addr := range t.addrs {
				if addr.Is4() == requested.Addr().Is4() && !used[addr] {
					used[addr] = true
					assigned[i] = netip.PrefixFrom(addr, addr.BitLen())
					break
				}
			}
		}
		var additional []netip.Prefix
		for _, addr := range t.addrs {
			if !used[addr] {
				additional = append(additional, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
		if err := req.Respond(assigned, additional); err != nil {
			return
		}
	}
}

func (s *Server) register(t *serverTunnel) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	for _, addr := range t.addrs {
		s.tunnels[addr] = t
	}
	return true
}

func (s *Server) release(t *serverTunnel) {
	s.mu.Lock()
	for _, addr := range t.addrs {
		if s.tunnels[addr] == t {
			delete(s.tunnels, addr)
		}
	}
	s.mu.Unlock()
	t.close()
	for _, addr := range t.addrs {
		for _, pool := range s.pools {
			if pool.prefix.Contains(addr) {
				pool.release(addr)
			}
		}
	}
}

func (s *Server) lookup(addr netip.Addr) *serverTunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[addr]
}

func (s *Server) inPool(addr netip.Addr) bool {
	return slices.ContainsFunc(s.pools, func(pool *addressPool) bool { return pool.prefix.Contains(addr) })
}

func (s *Server) readFromTunnel(t *serverTunnel) error {
	b := make([]byte, 1<<16)
	for {
		n, err := t.conn.Read(b)
		if err != nil {
			if go_errors.Is(err, io.ErrShortBuffer) {
				continue
			}
			if go_errors.Is(err, stdnet.ErrClosed) || go_errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		dst, ok := packetDestination(b[:n])
		if !ok || dst.IsLinkLocalUnicast() || dst.IsMulticast() {
			continue
		}
		if other := s.lookup(dst); other != nil {
			if other != t {
				packet := buf.NewWithSize(int32(n))
				packet.Write(b[:n])
				if !other.send(packet) {
					packet.Release()
				}
			}
			continue
		}
		if s.inPool(dst) && !slices.Contains(s.local, dst) {
			continue
		}
		s.dev.Write([][]byte{b[:n]}, 0)
	}
}

func (s *Server) readFromStack() {
	sizes := []int{0}
	var b *buf.Buffer
	for {
		if b == nil {
			b = buf.NewWithSize(int32(s.mtu))
		}
		b.Clear()
		if _, err := s.dev.Read([][]byte{b.Extend(int32(s.mtu))}, sizes, 0); err != nil {
			b.Release()
			return
		}
		b.Resize(0, int32(sizes[0]))
		dst, ok := packetDestination(b.Bytes())
		if !ok {
			continue
		}
		if t := s.lookup(dst); t != nil && t.send(b) {
			b = nil
		}
	}
}

func (s *Server) writeToTunnel(t *serverTunnel) {
	for {
		select {
		case b := <-t.queue:
			_, err := t.conn.Write(b.Bytes())
			b.Release()
			if ptb, ok := go_errors.AsType[*masque.PacketTooBigError](err); ok {
				s.dev.Write([][]byte{ptb.ICMP}, 0)
			}
		case <-t.done:
			return
		}
	}
}

func packetDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			return netip.AddrFrom4([4]byte(packet[16:20])), true
		}
	case 6:
		if len(packet) >= 40 {
			return netip.AddrFrom16([16]byte(packet[24:40])), true
		}
	}
	return netip.Addr{}, false
}

func (s *Server) handleConnection(conn net.Conn, dest net.Destination) {
	defer conn.Close()
	source := net.DestinationFromAddr(conn.RemoteAddr())
	addr, _ := netip.AddrFromSlice(source.Address.IP())
	t := s.lookup(addr.Unmap())
	if t == nil || !t.track(conn) {
		errors.LogInfo(s.ctx, "MASQUE: no tunnel for ", source, " to ", dest)
		return
	}
	defer t.untrack(conn)

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())
	inbound := session.Inbound{
		Name:          "masque",
		Tag:           s.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User:          t.user,
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: s.sniffing,
	})
	ctx = session.SubContextFromMuxInbound(ctx)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     dest,
		Status: log.AccessAccepted,
		Email:  t.user.Email,
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", dest)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := s.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
