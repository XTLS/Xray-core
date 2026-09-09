package realm

import (
	"context"
	goerrors "errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type realmConnClient struct {
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	net.PacketConn
	peer *net.UDPAddr

	realmClient   *Client
	realmID       string
	stunServers   []string
	family        Family
	mapper        *PortMapper
	stunTimeout   time.Duration
	punchTimeout  time.Duration
	punchInterval time.Duration
}

func NewConnClient(config *Config, raw net.PacketConn) (net.PacketConn, error) {
	ctx, cancel := context.WithCancel(context.Background())

	family := Family_Dual
	switch config.IPMode {
	case "dual":
	case "v4":
		family = Family_V4
	case "v6":
		family = Family_V6
	}

	var mapper *PortMapper
	if config.PortMapping != nil && config.PortMapping.Enabled {
		var err error
		start := time.Now()
		mapper, err = NewPortMapper(context.Background(), raw.LocalAddr().(*net.UDPAddr).Port, PortMapConfig{Timeout: time.Duration(config.PortMapping.Timeout) * time.Second, Lifetime: time.Duration(config.PortMapping.Lifetime) * time.Second})
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "[realm] [port mapping] [", raw.LocalAddr().(*net.UDPAddr).Port, "] init failed after ", time.Since(start))
		} else {
			errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] gateway ", mapper.GatewayType(), ", external ", mapper.ExternalAddr())
			errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] init success with ", time.Since(start))
		}
	}

	conn := &realmConnClient{
		ctx:        ctx,
		cancel:     cancel,
		PacketConn: raw,

		realmClient:   NewClient(config.Scheme, config.Host, config.Port, config.Token, config.TlsConfig),
		realmID:       config.ID,
		stunServers:   config.StunServers,
		family:        family,
		mapper:        mapper,
		stunTimeout:   defaultSTUNTimeout,
		punchTimeout:  defaultPunchTimeout,
		punchInterval: defaultPunchInterval,
	}
	return conn.getpeer()
}

func (c *realmConnClient) getpeer() (net.PacketConn, error) {
	start := time.Now()
	servers := resolveSTUNServers(c.PacketConn.LocalAddr().(*net.UDPAddr).IP, c.stunServers, c.family)
	errors.LogDebug(context.Background(), "[realm] update stun servers ", servers, " with ", time.Since(start))
	if len(servers) == 0 {
		return nil, errors.New("empty locals")
	}

	start = time.Now()
	locals := c.discover(servers)
	errors.LogDebug(context.Background(), "[realm] update stun locals ", locals, " with ", time.Since(start))
	if len(locals) == 0 {
		return nil, errors.New("empty locals")
	}

	meta := common.Must2(NewPunchMetadata())

	start = time.Now()
	resp, err := c.realmClient.Connect(context.Background(), c.realmID, ConnectRequest{
		Addresses:     addrPortStrings(locals),
		PunchMetadata: meta,
	})
	if err != nil {
		return nil, err
	}
	errors.LogDebug(context.Background(), "[realm] ", c.realmID, " ", meta.Nonce, " connect ", resp.Addresses, " with ", time.Since(start))

	peers, _ := parseAddrPorts(resp.Addresses)
	errors.LogDebug(context.Background(), "[realm] update peers ", peers)
	filteredPeers, seen := candidatePunchAddrs(locals, peers, c.family)
	errors.LogDebug(context.Background(), "[realm] filtered peers ", filteredPeers)
	expandedPeers := expandSymmetricNATCandidates(filteredPeers, seen)
	errors.LogDebug(context.Background(), "[realm] expanded peers ", expandedPeers)

	if len(expandedPeers) == 0 {
		return nil, errors.New("empty peers")
	}

	start = time.Now()
	peer, err := c.punch(meta, expandedPeers)
	if err != nil {
		return nil, errors.New("punch fail").Base(err)
	}
	errors.LogDebug(context.Background(), "[realm] punch peer ", peer, " with ", time.Since(start))

	if c.mapper != nil {
		c.wg.Add(1)
		go portMapLoop(c.ctx, c.mapper, c.wg.Done)
	}

	c.peer = peer
	return c, nil
}

func (c *realmConnClient) discover(servers []*net.UDPAddr) []netip.AddrPort {
	transactionIDs := make(map[[stun.TransactionIDSize]byte]struct{}, len(servers))
	for _, server := range servers {
		msg := common.Must2(stun.Build(stun.TransactionID, stun.BindingRequest))
		transactionIDs[msg.TransactionID] = struct{}{}
		_, _ = c.PacketConn.WriteTo(msg.Raw, server)
	}

	buf := make([]byte, 1500)
	results := make([]netip.AddrPort, 0, len(servers))
	c.PacketConn.SetReadDeadline(time.Now().Add(defaultSTUNTimeout))
	for len(transactionIDs) > 0 {
		n, _, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			break
		}
		msg, addrPort, err := parseSTUNBindingResponse(buf[:n])
		if err != nil {
			continue
		}
		if _, ok := transactionIDs[msg.TransactionID]; ok {
			delete(transactionIDs, msg.TransactionID)
			results = append(results, addrPort)
		}
	}
	c.PacketConn.SetReadDeadline(time.Time{})
	if c.mapper != nil {
		results = insertAddr(results, c.mapper.ExternalAddr())
	}
	slices.SortFunc(results, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
	return results
}

func (c *realmConnClient) punch(meta PunchMetadata, peers []netip.AddrPort) (*net.UDPAddr, error) {
	defer c.PacketConn.SetReadDeadline(time.Time{})
	nextSend := time.Now()
	deadline := nextSend.Add(c.punchTimeout)
	buf := make([]byte, punchMaxWireLen)
	for {
		now := time.Now()
		if now.After(deadline) {
			return nil, errors.New("timeout")
		}
		if now.After(nextSend) {
			for _, peer := range peers {
				packet := common.Must2(EncodePunchPacket(PunchPacketHello, meta))
				_, _ = c.PacketConn.WriteTo(packet, net.UDPAddrFromAddrPort(peer))
			}
			nextSend = now.Add(c.punchInterval)
		}

		if nextSend.After(deadline) {
			c.PacketConn.SetReadDeadline(deadline)
		} else {
			c.PacketConn.SetReadDeadline(nextSend)
		}
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, err
		}
		packet, err := DecodePunchPacket(buf[:n], meta)
		if err != nil {
			continue
		}
		if packet.Type == PunchPacketHello {
			packet := common.Must2(EncodePunchPacket(PunchPacketAck, meta))
			_, _ = c.PacketConn.WriteTo(packet, addr)
		}
		return addr.(*net.UDPAddr), nil
	}
}

func (c *realmConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(p, c.peer)
}

func (c *realmConnClient) Close() error {
	// Sadly, closing the core does not first close the sockets created for outbound connections
	c.cancel()
	c.wg.Wait()
	return nil
}

func portMapLoop(ctx context.Context, mapper *PortMapper, done func()) {
	defer func() {
		err := mapper.Close()
		done()
		errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] removed with ", err)
	}()
	interval := mapper.Lifetime() / 2
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := mapper.Renew(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !failing {
					errors.LogError(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] renewal failed")
					failing = true
				}
				continue
			}
			errors.LogDebug(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] external ", mapper.ExternalAddr(), ", changed ", changed)
			if failing {
				errors.LogError(context.Background(), "[realm] [port mapping] [", mapper.InternalPort(), "] recovered")
				failing = false
			}
		}
	}
}
