package internet

import (
	stdnet "net"
	"net/netip"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

type proxyProtocolListenerConfig struct {
	policy    proxyproto.ConnPolicyFunc
	validator proxyproto.Validator
}

var ipv6LinkLocalPrefix = netip.MustParsePrefix("fe80::/10")

// ValidateProxyProtocolConfig validates both JSON-built and programmatically
// constructed SocketConfig values before they are used by a listener.
func ValidateProxyProtocolConfig(config *SocketConfig) error {
	if config == nil {
		return nil
	}

	switch config.ProxyProtocolMode {
	case SocketConfig_ProxyProtocolDefault:
		if len(config.ProxyProtocolTrustedSources) > 0 {
			return errors.New("proxyProtocolTrustedSources requires proxyProtocolMode trusted-sources")
		}
		if len(config.ProxyProtocolListenPorts) > 0 {
			return errors.New("proxyProtocolListenPorts requires proxyProtocolMode trusted-sources")
		}
	case SocketConfig_ProxyProtocolTrustedSources:
		if config.AcceptProxyProtocol {
			return errors.New("acceptProxyProtocol cannot be combined with proxyProtocolMode trusted-sources")
		}
		if len(config.ProxyProtocolTrustedSources) == 0 {
			return errors.New("proxyProtocolMode trusted-sources requires a non-empty proxyProtocolTrustedSources list")
		}
		if _, err := parseProxyProtocolTrustedSources(config.ProxyProtocolTrustedSources); err != nil {
			return err
		}
		seenPorts := make(map[uint32]struct{}, len(config.ProxyProtocolListenPorts))
		for _, port := range config.ProxyProtocolListenPorts {
			if port == 0 || port > 65535 {
				return errors.New("invalid proxy protocol listen port: ", port)
			}
			if _, found := seenPorts[port]; found {
				return errors.New("duplicate proxy protocol listen port: ", port)
			}
			seenPorts[port] = struct{}{}
		}
	default:
		return errors.New("unsupported proxy protocol mode: ", config.ProxyProtocolMode)
	}

	return nil
}

// ValidateProxyProtocolTransportConfig rejects legacy transport-level PROXY
// flags when source-aware mode is active. Keeping the legacy bits clear makes
// mixed-version rollback fail closed instead of reverting to trust-all.
func ValidateProxyProtocolTransportConfig(config *SocketConfig, transportSettings interface{}) error {
	if err := ValidateProxyProtocolConfig(config); err != nil {
		return err
	}
	if config == nil || config.ProxyProtocolMode != SocketConfig_ProxyProtocolTrustedSources {
		return nil
	}
	if legacy, ok := transportSettings.(interface{ GetAcceptProxyProtocol() bool }); ok && legacy.GetAcceptProxyProtocol() {
		return errors.New("transport acceptProxyProtocol cannot be combined with proxyProtocolMode trusted-sources")
	}
	return nil
}

// ValidateProxyProtocolListenerSet validates settings that depend on the
// complete inbound listener set rather than on one listener at a time.
func ValidateProxyProtocolListenerSet(config *SocketConfig, listenerPorts *xnet.PortList) error {
	if err := ValidateProxyProtocolConfig(config); err != nil {
		return err
	}
	if config == nil || config.ProxyProtocolMode != SocketConfig_ProxyProtocolTrustedSources {
		return nil
	}
	if listenerPorts == nil {
		return errors.New("proxyProtocolMode trusted-sources requires TCP listener ports and is unsupported for Unix domain sockets")
	}
	if len(config.ProxyProtocolListenPorts) == 0 {
		return nil
	}

	for _, configuredPort := range config.ProxyProtocolListenPorts {
		matched := false
		for _, listenerRange := range listenerPorts.Range {
			if listenerRange.From <= configuredPort && configuredPort <= listenerRange.To {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("proxyProtocolListenPort does not belong to the inbound listener set: ", configuredPort)
		}
	}
	return nil
}

// ValidateProxyProtocolInboundConfig validates constraints that depend on the
// complete inbound network/listener set before any worker can open a socket.
func ValidateProxyProtocolInboundConfig(config *SocketConfig, listenerPorts *xnet.PortList, networks []xnet.Network, streamSettings *MemoryStreamConfig) error {
	if err := ValidateProxyProtocolListenerSet(config, listenerPorts); err != nil {
		return err
	}
	if config == nil || config.ProxyProtocolMode != SocketConfig_ProxyProtocolTrustedSources {
		return nil
	}
	if xnet.HasNetwork(networks, xnet.Network_UDP) {
		return errors.New("proxyProtocolMode trusted-sources does not support UDP or mixed TCP/UDP inbounds")
	}
	if err := validateProxyProtocolEffectiveTransport(streamSettings); err != nil {
		return err
	}
	return nil
}

// validateProxyProtocolEffectiveTransport rejects transports whose logical
// inbound network is TCP but whose actual listener is packet based. This must
// run before workers are created, because ListenPacket is otherwise reached
// only from Start and a hot AddInbound may already have registered its handler.
func validateProxyProtocolEffectiveTransport(streamSettings *MemoryStreamConfig) error {
	protocol := "tcp"
	if streamSettings != nil && streamSettings.ProtocolName != "" {
		protocol = streamSettings.ProtocolName
	}

	switch protocol {
	case "tcp", "websocket", "httpupgrade", "grpc":
		return nil
	case "splithttp":
		if streamSettings != nil && isHTTP3SecuritySettings(streamSettings.SecuritySettings) {
			return errors.New("proxyProtocolMode trusted-sources does not support the packet-based XHTTP-H3 listener")
		}
		return nil
	case "mkcp", "hysteria":
		return errors.New("proxyProtocolMode trusted-sources does not support packet-based transport: ", protocol)
	default:
		return errors.New("proxyProtocolMode trusted-sources does not support unknown effective transport: ", protocol)
	}
}

func isHTTP3SecuritySettings(settings interface{}) bool {
	nextProtocolSettings, ok := settings.(interface{ GetNextProtocol() []string })
	if !ok {
		return false
	}
	nextProtocols := nextProtocolSettings.GetNextProtocol()
	return len(nextProtocols) == 1 && nextProtocols[0] == "h3"
}

// CanUseXForwardedFor reports whether an HTTP transport listener may replace
// its socket peer address with a forwarded header. The decision is made from
// the configured listener port before any PROXY-derived LocalAddr is applied.
func CanUseXForwardedFor(config *SocketConfig, listenerPort uint32) bool {
	if config == nil || config.ProxyProtocolMode != SocketConfig_ProxyProtocolTrustedSources {
		return true
	}
	if len(config.ProxyProtocolListenPorts) == 0 {
		return false
	}
	return !containsProxyProtocolPort(config.ProxyProtocolListenPorts, listenerPort)
}

func parseProxyProtocolTrustedSources(sources []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(sources))
	for _, source := range sources {
		if addr, err := netip.ParseAddr(source); err == nil {
			if addr.Zone() != "" {
				return nil, errors.New("proxy protocol trusted source must not contain an IPv6 zone: ", source)
			}
			addr = addr.Unmap()
			if addr.Is6() && addr.IsLinkLocalUnicast() {
				return nil, errors.New("IPv6 link-local proxy protocol trusted sources are unsupported: ", source)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}

		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			return nil, errors.New("invalid proxy protocol trusted source: ", source).Base(err)
		}
		if prefix.Addr().Zone() != "" {
			return nil, errors.New("proxy protocol trusted source must not contain an IPv6 zone: ", source)
		}
		if prefix.Addr().Is4In6() {
			return nil, errors.New("IPv4-mapped proxy protocol prefixes are unsupported; use an IPv4 prefix: ", source)
		}
		if prefix != prefix.Masked() {
			return nil, errors.New("proxy protocol trusted CIDR must use its canonical network address: ", source)
		}
		if prefix.Addr().Is6() && prefix.Overlaps(ipv6LinkLocalPrefix) {
			return nil, errors.New("IPv6 link-local proxy protocol trusted prefixes are unsupported: ", source)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func newProxyProtocolListenerConfig(addr stdnet.Addr, socketConfig *SocketConfig) (*proxyProtocolListenerConfig, error) {
	if err := ValidateProxyProtocolConfig(socketConfig); err != nil {
		return nil, err
	}
	if socketConfig == nil {
		return nil, nil
	}

	if socketConfig.ProxyProtocolMode == SocketConfig_ProxyProtocolDefault {
		if !socketConfig.AcceptProxyProtocol {
			return nil, nil
		}
		return &proxyProtocolListenerConfig{
			policy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}, nil
	}

	tcpListener, ok := addr.(*stdnet.TCPAddr)
	if !ok {
		if _, unix := addr.(*stdnet.UnixAddr); unix {
			return nil, errors.New("proxyProtocolMode trusted-sources is unsupported for Unix domain sockets")
		}
		return nil, errors.New("proxyProtocolMode trusted-sources requires a TCP listener")
	}

	dedicatedPort := len(socketConfig.ProxyProtocolListenPorts) > 0
	if dedicatedPort && tcpListener.Port == 0 {
		return nil, errors.New("proxyProtocolListenPorts cannot be selected before binding TCP port 0")
	}
	if dedicatedPort && !containsProxyProtocolPort(socketConfig.ProxyProtocolListenPorts, uint32(tcpListener.Port)) {
		return nil, nil
	}

	trustedPrefixes, err := parseProxyProtocolTrustedSources(socketConfig.ProxyProtocolTrustedSources)
	if err != nil {
		return nil, err
	}

	return &proxyProtocolListenerConfig{
		policy: func(connOpts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			upstream, ok := connOpts.Upstream.(*stdnet.TCPAddr)
			if ok && upstream.IP != nil && upstream.Zone == "" {
				if upstreamAddr, valid := netip.AddrFromSlice(upstream.IP); valid {
					upstreamAddr = upstreamAddr.Unmap()
					for _, prefix := range trustedPrefixes {
						if prefix.Contains(upstreamAddr) {
							return proxyproto.REQUIRE, nil
						}
					}
				}
			}
			if dedicatedPort {
				return proxyproto.SKIP, proxyproto.ErrInvalidUpstream
			}
			return proxyproto.SKIP, nil
		},
		validator: validateSourceAwareProxyHeader,
	}, nil
}

func containsProxyProtocolPort(ports []uint32, port uint32) bool {
	for _, allowed := range ports {
		if allowed == port {
			return true
		}
	}
	return false
}

func validateSourceAwareProxyHeader(header *proxyproto.Header) error {
	if header == nil {
		return errors.New("missing PROXY protocol header")
	}
	if header.Version != 2 {
		return errors.New("PROXY protocol v2 is required")
	}
	if _, err := header.TLVs(); err != nil {
		return errors.New("invalid PROXY protocol v2 TLVs").Base(err)
	}
	if header.Command != proxyproto.PROXY {
		return errors.New("PROXY command is required")
	}
	if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
		return errors.New("TCPv4 or TCPv6 PROXY transport is required")
	}
	source, destination, ok := header.TCPAddrs()
	if !ok || source == nil || destination == nil {
		return errors.New("TCP source and destination addresses are required")
	}
	if source.IP == nil || source.IP.IsUnspecified() || source.IP.IsMulticast() || isIPv4LimitedBroadcast(source.IP) || source.Port <= 0 || source.Port > 65535 {
		return errors.New("a valid client source address is required")
	}
	if destination.IP == nil || destination.IP.IsUnspecified() || destination.IP.IsMulticast() || isIPv4LimitedBroadcast(destination.IP) || destination.Port <= 0 || destination.Port > 65535 {
		return errors.New("a valid destination address is required")
	}
	return nil
}

func isIPv4LimitedBroadcast(ip stdnet.IP) bool {
	ipv4 := ip.To4()
	return ipv4 != nil && ipv4.Equal(stdnet.IPv4bcast)
}
