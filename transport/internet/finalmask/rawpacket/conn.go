package rawpacket

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

func (c *Config) TCP() {}

func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	if !PlatformSupported {
		return nil, fmt.Errorf("rawpacket is not supported on this platform")
	}

	mode := c.Mode
	if mode == "" {
		mode = "local"
	}

	switch mode {
	case "local":
		return c.dialLocal()
	case "remote":
		return nil, fmt.Errorf("rawpacket: remote mode must be used as server")
	default:
		return nil, fmt.Errorf("rawpacket: unknown mode: %s", mode)
	}
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	if c.Mode == "remote" {
		go c.startRelay()
		return raw, nil
	}
	return raw, nil
}

func toNetIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

func toNetipAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func (c *Config) dialLocal() (net.Conn, error) {
	remoteIP := c.RemoteAddress
	if remoteIP == "" {
		return nil, fmt.Errorf("rawpacket: remoteAddress required")
	}
	remotePort := uint16(c.RemotePort)
	if remotePort == 0 {
		remotePort = 443
	}

	recvPort := uint16(c.RecvPort)
	if recvPort == 0 {
		recvPort = 60000
	}

	spoofIPs := c.SpoofIps
	if len(spoofIPs) == 0 {
		return nil, fmt.Errorf("rawpacket: at least one spoof IP required")
	}

	ttl := uint8(c.Ttl)
	if ttl == 0 {
		ttl = 64
	}

	sendProto := c.SendTransport
	if sendProto == "" {
		sendProto = "tcp"
	}

	recvProto := c.RecvTransport
	if recvProto == "" {
		recvProto = "udp"
	}

	relayAddrPort, err := netip.ParseAddrPort(net.JoinHostPort(remoteIP, strconv.Itoa(int(remotePort))))
	if err != nil {
		return nil, fmt.Errorf("rawpacket: parse remote address: %w", err)
	}

	ips, err := ParseIPs(spoofIPs)
	if err != nil {
		return nil, err
	}

	return DialSpoof(relayAddrPort, ips, recvPort, ttl, sendProto, recvProto, toNetipAddr(c.PeerSpoofIp))
}

func (c *Config) startRelay() {
	cfg, err := c.buildRelayConfig()
	if err != nil {
		return
	}
	r, err := NewRelay(cfg)
	if err != nil {
		return
	}
	defer r.Close()
	r.Run()
}

func (c *Config) buildRelayConfig() (*RelayConfig, error) {
	spoofIPs := c.SpoofIps
	if len(spoofIPs) == 0 {
		return nil, fmt.Errorf("rawpacket: at least one spoof IP required for relay")
	}

	target := c.Target
	if target == "" {
		target = "127.0.0.1:443"
	}

	relayPort := uint16(c.RelayPort)
	if relayPort == 0 {
		relayPort = 443
	}

	sendProto := c.SendTransport
	if sendProto == "" {
		sendProto = "udp"
	}

	recvProto := c.RecvTransport
	if recvProto == "" {
		recvProto = "tcp"
	}

	clientIP := c.ClientIp
	clientPort := uint16(c.ClientPort)

	if clientIP == "" {
		clientIP = firstStr(spoofIPs)
	}
	if clientPort == 0 {
		clientPort = uint16(c.RecvPort)
		if clientPort == 0 {
			clientPort = 60000
		}
	}

	spoofPort := uint16(c.SpoofPort)
	if spoofPort == 0 {
		spoofPort = 443
	}

	fwdTransport := c.SendTransport
	if fwdTransport == "udp" {
		fwdTransport = "udp"
	} else {
		fwdTransport = "tcp"
	}

	return &RelayConfig{
		ListenPort:       relayPort,
		ForwardAddr:      target,
		ForwardTransport: fwdTransport,
		ClientIP:         toNetipAddr(clientIP),
		ClientPort:       clientPort,
		SpoofIPs:         spoofIPs,
		SpoofPort:        spoofPort,
		PeerSpoofIP:      toNetipAddr(c.PeerSpoofIp),
		SendTransport:    sendProto,
		RecvTransport:    recvProto,
	}, nil
}

func firstStr(ss []string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return ""
}
