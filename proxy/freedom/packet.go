package freedom

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/exchange"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// freedomPacketIO owns addressing and final-rule handling for both the old
// local MultiBuffer codec and the new addressed packet endpoint.
type freedomPacketIO struct {
	ctx          context.Context
	conn         stat.Connection
	packet       net.PacketConn
	h            *Handler
	defaultRule  *FinalRule
	override     net.Destination
	dialDest     net.Destination
	outGateway   net.Address
	resolved     *utils.TypedSyncMap[string, net.Address]
	readCounter  stats.Counter
	writeCounter stats.Counter
	changedAddr  net.Address
	originalDest net.Destination
	firstWrite   bool
	pendingRead  error
}

func newFreedomPacketIO(conn stat.Connection, h *Handler, defaultRule *FinalRule, override, dialDest net.Destination, outGateway net.Address) (*freedomPacketIO, bool) {
	raw := stat.TryUnwrapStatsConn(conn)
	packet, ok := raw.(net.PacketConn)
	if !ok {
		return nil, false
	}
	p := &freedomPacketIO{conn: conn, packet: packet, h: h, defaultRule: defaultRule, override: override, dialDest: dialDest, outGateway: outGateway, resolved: utils.NewTypedSyncMap[string, net.Address](), firstWrite: true}
	if c, ok := conn.(*stat.CounterConnection); ok {
		p.readCounter, p.writeCounter = c.ReadCounter, c.WriteCounter
	}
	if dest := net.DestinationFromAddr(conn.RemoteAddr()); dest.IsValid() {
		p.changedAddr = dest.Address
	}
	if dialDest.Address != nil && dialDest.Address.Family().IsDomain() && p.changedAddr != nil {
		p.resolved.Store(dialDest.Address.Domain(), p.changedAddr)
	}
	return p, true
}

func (p *freedomPacketIO) ReadPacket(data []byte) (int, net.Destination, error) {
	for {
		if p.pendingRead != nil {
			err := p.pendingRead
			p.pendingRead = nil
			return 0, net.Destination{}, err
		}
		n, addr, err := p.packet.ReadFrom(data)
		if err != nil && n == 0 {
			return 0, net.Destination{}, err
		}
		if err != nil {
			p.pendingRead = err
		}
		from := net.DestinationFromAddr(addr)
		if !from.IsValid() {
			return 0, net.Destination{}, errors.New("packet source address unavailable")
		}
		if rule := p.h.matchFinalRule(net.Network_UDP, from.Address, from.Port, p.defaultRule); rule != nil && rule.action == RuleAction_Block {
			continue
		}
		if p.override.Address != nil || p.override.Port != 0 {
			if p.originalDest.IsValid() {
				from = p.originalDest
			} else {
				from = p.dialDest
			}
		} else if p.changedAddr != nil && from.Address == p.changedAddr {
			from.Address = p.dialDest.Address
		}
		if p.readCounter != nil {
			p.readCounter.Add(int64(n))
		}
		return n, from, nil
	}
}

func (p *freedomPacketIO) WritePacket(data []byte, dest net.Destination) (int, error) {
	if p.firstWrite {
		p.firstWrite = false
		if err := p.emitNoise(); err != nil {
			return 0, err
		}
	}
	if p.override.Address != nil {
		dest.Address = p.override.Address
	}
	if p.override.Port != 0 {
		dest.Port = p.override.Port
	}
	if dest.Address == nil {
		return len(data), nil
	}
	if dest.Address.Family().IsDomain() {
		domain := dest.Address.Domain()
		if ip, ok := p.resolved.Load(domain); ok {
			dest.Address = ip
		} else {
			var ip net.Address
			if strategy := p.h.resolveStrategy; strategy.HasStrategy() {
				ips, err := internet.LookupForIP(domain, strategy, p.outGateway)
				if err != nil && strategy.ForceIP() {
					return len(data), nil
				}
				if len(ips) > 0 {
					ip = net.IPAddress(ips[dice.Roll(len(ips))])
				}
			}
			if ip == nil {
				udpAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
				if err != nil {
					return len(data), nil
				}
				ip = net.IPAddress(udpAddr.IP)
			}
			if ip != nil {
				dest.Address, _ = p.resolved.LoadOrStore(domain, ip)
			}
		}
	}
	if rule := p.h.matchFinalRule(net.Network_UDP, dest.Address, dest.Port, p.defaultRule); rule != nil && rule.action == RuleAction_Block {
		return len(data), nil
	}
	addr := dest.RawNetAddr()
	if addr == nil {
		return len(data), nil
	}
	n, err := p.packet.WriteTo(data, addr)
	if p.writeCounter != nil && n > 0 {
		p.writeCounter.Add(int64(n))
	}
	return n, err
}

func (p *freedomPacketIO) WriteDefaultPacket(data []byte) (int, error) {
	if p.firstWrite {
		p.firstWrite = false
		if err := p.emitNoise(); err != nil {
			return 0, err
		}
	}
	n, err := p.packet.WriteTo(data, p.conn.RemoteAddr())
	if p.writeCounter != nil && n > 0 {
		p.writeCounter.Add(int64(n))
	}
	return n, err
}

func (p *freedomPacketIO) emitNoise() error {
	if p.h.config.Noises == nil || p.override.Port == 53 {
		return nil
	}
	remote := net.DestinationFromAddr(p.conn.RemoteAddr()).Address
	for _, noise := range p.h.config.Noises {
		switch noise.ApplyTo {
		case "ipv4":
			if remote.Family().IsIPv6() {
				continue
			}
		case "ipv6":
			if remote.Family().IsIPv4() {
				continue
			}
		case "ip":
		default:
			continue
		}
		payload := noise.Packet
		if payload == nil {
			var err error
			payload, err = GenerateRandomBytes(crypto.RandBetween(int64(noise.LengthMin), int64(noise.LengthMax)))
			if err != nil {
				return err
			}
		}
		n, err := p.packet.WriteTo(payload, p.conn.RemoteAddr())
		if p.writeCounter != nil && n > 0 {
			p.writeCounter.Add(int64(n))
		}
		if err != nil {
			return err
		}
		if noise.DelayMin != 0 || noise.DelayMax != 0 {
			delay := time.NewTimer(time.Duration(crypto.RandBetween(int64(noise.DelayMin), int64(noise.DelayMax))) * time.Millisecond)
			if p.ctx != nil {
				select {
				case <-delay.C:
				case <-p.ctx.Done():
					delay.Stop()
					return p.ctx.Err()
				}
			} else {
				<-delay.C
			}
		}
	}
	return nil
}

type blockedPacketReader struct{ ctx context.Context }

func (b blockedPacketReader) ReadPacket([]byte) (int, net.Destination, error) {
	<-b.ctx.Done()
	return 0, net.Destination{}, b.ctx.Err()
}

type discardPacketWriter struct{}

func (discardPacketWriter) WritePacket(data []byte, _ net.Destination) (int, error) {
	return len(data), nil
}

func (h *Handler) PreparePacket(ctx context.Context, dialer internet.Dialer) (exchange.PacketEndpoint, error) {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return exchange.PacketEndpoint{}, errors.New("packet target not specified")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() || ob.Target.Network != net.Network_UDP {
		return exchange.PacketEndpoint{}, errors.New("invalid Freedom packet target")
	}
	ob.Name = "freedom"
	inbound := session.InboundFromContext(ctx)
	var defaultRule *FinalRule
	if !h.usesDialerProxy {
		defaultRule = getDefaultFinalRule(inbound)
	}
	destination := ob.Target
	override := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			override.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			override.Port = destination.Port
		}
	}
	dialer.SetOutboundGateway(ctx, ob)
	conn, blockedRule, blocked, err := h.openConnection(ctx, dialer, destination, defaultRule, ob.Gateway, inbound)
	if err != nil {
		return exchange.PacketEndpoint{}, err
	}
	if blocked != nil {
		blockCtx, cancel := context.WithCancel(ctx)
		end := time.AfterFunc(h.blockDelay(blockedRule), cancel)
		return exchange.PacketEndpoint{Reader: blockedPacketReader{ctx: blockCtx}, Writer: discardPacketWriter{}, Abort: func() { end.Stop(); cancel() }}, nil
	}
	packet, ok := newFreedomPacketIO(conn, h, defaultRule, override, destination, ob.Gateway)
	if !ok {
		_ = conn.Close()
		return exchange.PacketEndpoint{}, errors.New("Freedom UDP dial did not return a packet-capable connection")
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return exchange.PacketEndpoint{}, err
	}
	packet.originalDest = ob.Target
	packet.ctx = ctx
	idle := h.policy().Timeouts.ConnectionIdle
	return exchange.PacketEndpoint{Reader: packet, Writer: packet, Abort: func() { _ = conn.Close() }, IdleTimeout: &idle}, nil
}
