package realm

import (
	"context"
	go_errors "errors"
	"net"
	"net/netip"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func NewRealmPeer(config *internet.RealmConfig, raw net.PacketConn) (*net.UDPAddr, error) {
	start := time.Now()
	servers := resolveSTUNServers(raw.LocalAddr().(*net.UDPAddr).IP, config.StunServers)
	errors.LogInfo(context.Background(), "[realm] get stun servers ", servers, " with ", time.Since(start))
	if len(servers) == 0 {
		return nil, errors.New("empty stun servers")
	}

	start = time.Now()
	locals := Discover(raw, servers)
	errors.LogInfo(context.Background(), "[realm] get stun locals ", locals, " with ", time.Since(start))
	if len(locals) == 0 {
		return nil, errors.New("empty stun locals")
	}

	rClient, err := NewClient(config.Scheme, config.Host, config.Port, config.Token)
	if err != nil {
		return nil, errors.New("http create").Base(err)
	}

	meta := common.Must2(NewPunchMetadata())

	start = time.Now()
	resp, err := rClient.Connect(context.Background(), config.ID, ConnectRequest{
		Addresses:     addrPortStrings(locals),
		PunchMetadata: meta,
	})
	if err != nil {
		return nil, errors.New("http connect").Base(err)
	}
	errors.LogInfo(context.Background(), "[realm] ", config.ID, " ", meta.Nonce, " connect with ", time.Since(start))

	errors.LogDebug(context.Background(), "[realm] get peers ", resp.Addresses)
	peers, err := parseAddrPorts(resp.Addresses)
	if err != nil {
		return nil, errors.New("invalid peers").Base(err)
	}

	filteredPeers, seen := candidatePunchAddrs(locals, peers)
	errors.LogDebug(context.Background(), "[realm] filtered peers ", filteredPeers)

	expandedPeers := expandSymmetricNATCandidates(filteredPeers, seen)
	errors.LogDebug(context.Background(), "[realm] expanded peers ", expandedPeers)

	if len(expandedPeers) == 0 {
		return nil, errors.New("empty peers")
	}

	start = time.Now()
	result, err := Punch(raw, expandedPeers, meta, defaultPunchTimeout, defaultPunchInterval)
	if err != nil {
		return nil, errors.New("punch fail").Base(err)
	}
	errors.LogInfo(context.Background(), "[realm] punch peer ", result, " with ", time.Since(start))

	return result, nil
}

func Punch(conn net.PacketConn, peers []netip.AddrPort, meta PunchMetadata, timeout, interval time.Duration) (*net.UDPAddr, error) {
	defer conn.SetReadDeadline(time.Time{})
	nextSend := time.Now()
	deadline := nextSend.Add(timeout)
	buf := make([]byte, punchMaxWireLen)
	for {
		now := time.Now()
		if now.After(nextSend) {
			sendPunchPackets(conn, peers, meta, PunchPacketHello)
			nextSend = now.Add(interval)
		}

		if nextSend.After(deadline) {
			conn.SetReadDeadline(deadline)
		} else {
			conn.SetReadDeadline(nextSend)
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if go_errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return nil, err
		}
		packet, err := DecodePunchPacket(buf[:n], meta)
		if err != nil {
			continue
		}
		if packet.Type == PunchPacketHello {
			sendPunchPacket(conn, addr.(*net.UDPAddr).AddrPort(), meta, PunchPacketAck)
		}
		return addr.(*net.UDPAddr), nil
	}
}
