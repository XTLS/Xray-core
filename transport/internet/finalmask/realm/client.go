package realm

import (
	"context"
	goerrors "errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type realmConnClient struct {
	net.PacketConn
	peer *net.UDPAddr

	realmClient   *Client
	realmID       string
	stunServers   []string
	stunTimeout   time.Duration
	punchTimeout  time.Duration
	punchInterval time.Duration
}

func NewConnClient(config *Config, raw net.PacketConn) (net.PacketConn, error) {
	conn := &realmConnClient{
		PacketConn: raw,

		realmClient:   NewClient(config.Scheme, config.Host, config.Port, config.Token, config.TlsConfig),
		realmID:       config.ID,
		stunServers:   config.StunServers,
		stunTimeout:   defaultSTUNTimeout,
		punchTimeout:  defaultPunchTimeout,
		punchInterval: defaultPunchInterval,
	}

	return conn.getpeer()
}

func (c *realmConnClient) getpeer() (net.PacketConn, error) {
	start := time.Now()
	servers := resolveSTUNServers(c.PacketConn.LocalAddr().(*net.UDPAddr).IP, c.stunServers)
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
	filteredPeers, seen := candidatePunchAddrs(locals, peers)
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
