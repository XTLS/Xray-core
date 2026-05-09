package freedom

import (
	"context"
	"crypto/rand"
	"io"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var useSplice bool
var allNetworks [8]bool
var defaultBlockPrivateRule *FinalRule
var defaultBlockAllRule *FinalRule

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))

	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useSplice = true
	}

	for i := range allNetworks {
		allNetworks[i] = true
	}

	defaultBlockPrivateRule = &FinalRule{
		action:  RuleAction_Block,
		network: allNetworks,
		ip: common.Must2(geodata.IPReg.BuildIPMatcher(common.Must2(geodata.ParseIPRules([]string{
			"0.0.0.0/8",
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"192.168.0.0/16",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"224.0.0.0/3",
			"::/127",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8",
		})))),
	}

	defaultBlockAllRule = &FinalRule{
		action:  RuleAction_Block,
		network: allNetworks,
	}
}

type FinalRule struct {
	action     RuleAction
	network    [8]bool
	port       net.MemoryPortList
	ip         geodata.IPMatcher
	blockDelay *Range
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	config        *Config
	finalRules    []*FinalRule
}

func buildFinalRule(config *FinalRuleConfig) (*FinalRule, error) {
	rule := &FinalRule{
		action:     config.GetAction(),
		blockDelay: config.GetBlockDelay(),
	}

	if len(config.Networks) == 0 {
		rule.network = allNetworks
	} else {
		for _, network := range config.Networks {
			rule.network[int(network)] = true
		}
	}

	if config.PortList != nil {
		rule.port = net.PortListFromProto(config.PortList)
	}

	if len(config.Ip) > 0 {
		matcher, err := geodata.IPReg.BuildIPMatcher(config.Ip)
		if err != nil {
			return nil, err
		}
		rule.ip = matcher
	}

	return rule, nil
}

func (r *FinalRule) matchNetwork(network net.Network) bool {
	return r.network[int(network)]
}

func (r *FinalRule) matchPort(port net.Port) bool {
	if len(r.port) == 0 {
		return true
	}
	return r.port.Contains(port)
}

func (r *FinalRule) matchIP(addr net.Address) bool {
	if r.ip == nil {
		return true
	}
	return addr != nil && addr.Family().IsIP() && r.ip.Match(addr.IP())
}

func (r *FinalRule) Apply(network net.Network, address net.Address, port net.Port) bool {
	if !r.matchNetwork(network) {
		return false
	}
	if !r.matchPort(port) {
		return false
	}
	return r.matchIP(address)
}

func getDefaultFinalRule(inbound *session.Inbound) *FinalRule {
	if inbound == nil {
		return nil
	}
	switch inbound.Name {
	case "vless-reverse":
		return defaultBlockAllRule
	case "vless", "vmess", "trojan", "hysteria", "wireguard":
		return defaultBlockPrivateRule
	default:
		if strings.HasPrefix(inbound.Name, "shadowsocks") {
			return defaultBlockPrivateRule
		}
	}
	return nil
}

func (h *Handler) shouldResolveDomainBeforeFinalRules(dialDest net.Destination, defaultRule *FinalRule) bool {
	if !dialDest.Address.Family().IsDomain() {
		return false
	}
	if len(h.finalRules) > 0 {
		rule := h.finalRules[0]
		if rule.action == RuleAction_Allow && rule.network[dialDest.Network] && len(rule.port) == 0 && rule.ip == nil {
			return false
		}
	}
	if defaultRule != nil || len(h.finalRules) > 0 {
		return true
	}
	return false
}

func (h *Handler) matchFinalRule(network net.Network, address net.Address, port net.Port, defaultRule *FinalRule) *FinalRule {
	for _, rule := range h.finalRules {
		if rule.Apply(network, address, port) {
			return rule
		}
	}
	if defaultRule != nil && defaultRule.Apply(network, address, port) {
		return defaultRule
	}
	return nil
}

func (h *Handler) applyFinalRules(network net.Network, address net.Address, port net.Port, defaultRule *FinalRule) RuleAction {
	if rule := h.matchFinalRule(network, address, port, defaultRule); rule != nil {
		return rule.action
	}
	return RuleAction_Allow
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	h.finalRules = make([]*FinalRule, 0, len(config.FinalRules))
	for _, rc := range config.FinalRules {
		rule, err := buildFinalRule(rc)
		if err != nil {
			return errors.New("failed to build final rule").Base(err)
		}
		h.finalRules = append(h.finalRules, rule)
	}
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

func (h *Handler) blockDelay(rule *FinalRule) time.Duration {
	min := uint64(30)
	max := uint64(90)
	if rule.blockDelay != nil {
		min = rule.blockDelay.Min
		max = rule.blockDelay.Max
	}
	span := max - min
	if max < min {
		span = min - max
	}
	return time.Duration(min+uint64(dice.Roll(int(span+1)))) * time.Second
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP && a != net.AnyIPv6
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "freedom"
	ob.CanSpliceCopy = 1
	inbound := session.InboundFromContext(ctx)
	defaultRule := getDefaultFinalRule(inbound)

	destination := ob.Target
	origTargetAddr := ob.OriginalTarget.Address
	if origTargetAddr == nil {
		origTargetAddr = ob.Target.Address
	}
	dialer.SetOutboundGateway(ctx, ob)
	outGateway := ob.Gateway
	UDPOverride := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			UDPOverride.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			UDPOverride.Port = destination.Port
		}
	}

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	var blockedDest *net.Destination
	var blockedRule *FinalRule
	firstResolve := true
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dialDest := destination
		if h.config.DomainStrategy.HasStrategy() && dialDest.Address.Family().IsDomain() {
			strategy := h.config.DomainStrategy
			if destination.Network == net.Network_UDP && origTargetAddr != nil && outGateway == nil {
				strategy = strategy.GetDynamicStrategy(origTargetAddr.Family())
			}
			ips, err := internet.LookupForIP(dialDest.Address.Domain(), strategy, outGateway)
			if err != nil {
				errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", dialDest.Address.Domain())
				if h.config.DomainStrategy.ForceIP() || h.shouldResolveDomainBeforeFinalRules(dialDest, defaultRule) {
					return err
				}
			} else {
				dialDest = net.Destination{
					Network: dialDest.Network,
					Address: net.IPAddress(ips[dice.Roll(len(ips))]),
					Port:    dialDest.Port,
				}
				errors.LogInfo(ctx, "dialing to ", dialDest)
			}
		} else if h.shouldResolveDomainBeforeFinalRules(dialDest, defaultRule) { // asis + domain + hasrules
			domain := dialDest.Address.Domain()
			var ips []net.IP
			if firstResolve {
				firstResolve = false
				supportIPv4, supportIPv6 := utils.CheckRoutes()
				if supportIPv4 {
					ips, _ = net.DefaultResolver.LookupIP(ctx, "ip4", domain)
				}
				if len(ips) == 0 && supportIPv6 {
					ips, _ = net.DefaultResolver.LookupIP(ctx, "ip6", domain)
				}
				if len(ips) == 0 {
					return errors.New("failed to get IP address for domain ", domain)
				}
			} else {
				ips, _ = net.DefaultResolver.LookupIP(ctx, "ip", domain)
			}
			if len(ips) == 0 { // SRV/TXT, lookup failed
				return errors.New("failed to get IP address for domain ", domain)
			}
			if addr := net.IPAddress(ips[dice.Roll(len(ips))]); addr != nil {
				dialDest.Address = addr
				errors.LogInfo(ctx, "dialing to ", dialDest)
			}
		}
		if rule := h.matchFinalRule(dialDest.Network, dialDest.Address, dialDest.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
			blockedDest = &dialDest
			blockedRule = rule
			return nil
		}

		rawConn, err := dialer.Dial(ctx, dialDest)
		if err != nil {
			return err
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	if blockedDest != nil {
		delay := h.blockDelay(blockedRule)
		errors.LogInfo(ctx, "blocked target: ", *blockedDest, ", blackholing connection for ", delay)
		timer := time.AfterFunc(delay, func() {
			common.Interrupt(input)
			common.Interrupt(output)
			errors.LogInfo(ctx, "closed blackholed connection to blocked target: ", *blockedDest)
		})
		defer timer.Stop()
		defer common.Close(output)
		if err := buf.Copy(input, buf.Discard); err != nil {
			return nil
		}
		return nil
	}
	if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
		version := byte(h.config.ProxyProtocol)
		srcAddr := inbound.Source.RawNetAddr()
		dstAddr := conn.RemoteAddr()
		header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
		if _, err = header.WriteTo(conn); err != nil {
			conn.Close()
			return errors.New("failed to set PROXY protocol v", version).Base(err)
		}
	}
	defer conn.Close()
	errors.LogInfo(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			if h.config.Fragment != nil {
				errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
					h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax, h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
				writer = buf.NewWriter(&FragmentWriter{
					fragment: h.config.Fragment,
					writer:   conn,
				})
			} else {
				writer = buf.NewWriter(conn)
			}
		} else {
			writer = NewPacketWriter(conn, h, defaultRule, UDPOverride, destination)
			if h.config.Noises != nil {
				errors.LogDebug(ctx, "NOISE", h.config.Noises)
				writer = &NoisePacketWriter{
					Writer:      writer,
					noises:      h.config.Noises,
					firstWrite:  true,
					UDPOverride: UDPOverride,
					remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
				}
			}
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if destination.Network == net.Network_TCP && useSplice && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = NewPacketReader(conn, h, defaultRule, UDPOverride, destination)
		}
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func NewPacketReader(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			DefaultRule:       defaultRule,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	stats.Counter
	Handler           *Handler
	DefaultRule       *FinalRule
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	for {
		n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
		if err != nil {
			b.Release()
			return nil, err
		}
		udpAddr := d.(*net.UDPAddr)
		sourceAddr := net.IPAddress(udpAddr.IP)
		if r.Handler.applyFinalRules(net.Network_UDP, sourceAddr, net.Port(udpAddr.Port), r.DefaultRule) == RuleAction_Block {
			continue
		}
		b.Resize(0, int32(n))

		// if udp dest addr is changed, we are unable to get the correct src addr
		// so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
		if !r.IsOverridden {
			if r.InitChangedAddr == sourceAddr {
				sourceAddr = r.InitUnchangedAddr
			}
			b.UDP = &net.Destination{
				Address: sourceAddr,
				Port:    net.Port(udpAddr.Port),
				Network: net.Network_UDP,
			}
		}
		if r.Counter != nil {
			r.Counter.Add(int64(n))
		}
		return buf.MultiBuffer{b}, nil
	}
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		// If DialDest is a domain, it will be resolved in dialer
		// check this behavior and add it to map
		resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
		if DialDest.Address.Family().IsDomain() {
			resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
		}
		return &PacketWriter{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			DefaultRule:       defaultRule,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			LocalAddr:         net.DestinationFromAddr(conn.LocalAddr()).Address,
		}

	}
	return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	stats.Counter
	*Handler
	DefaultRule *FinalRule
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	LocalAddr       net.Address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var n int
		var err error
		if b.UDP != nil {
			if w.UDPOverride.Address != nil {
				b.UDP.Address = w.UDPOverride.Address
			}
			if w.UDPOverride.Port != 0 {
				b.UDP.Port = w.UDPOverride.Port
			}
			if b.UDP.Address.Family().IsDomain() {
				if ip, ok := w.ResolvedUDPAddr.Load(b.UDP.Address.Domain()); ok {
					b.UDP.Address = ip
				} else {
					ShouldUseSystemResolver := true
					if w.Handler.config.DomainStrategy.HasStrategy() {
						ips, err := internet.LookupForIP(b.UDP.Address.Domain(), w.Handler.config.DomainStrategy, w.LocalAddr)
						if err != nil {
							// drop packet if resolve failed when forceIP
							if w.Handler.config.DomainStrategy.ForceIP() {
								b.Release()
								continue
							}
						} else {
							ip = net.IPAddress(ips[dice.Roll(len(ips))])
							ShouldUseSystemResolver = false
						}
					}
					if ShouldUseSystemResolver {
						udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
						if err != nil {
							b.Release()
							continue
						} else {
							ip = net.IPAddress(udpAddr.IP)
						}
					}
					if ip != nil {
						b.UDP.Address, _ = w.ResolvedUDPAddr.LoadOrStore(b.UDP.Address.Domain(), ip)
					}
				}
			}
			if w.applyFinalRules(net.Network_UDP, b.UDP.Address, b.UDP.Port, w.DefaultRule) == RuleAction_Block {
				b.Release()
				continue
			}
			destAddr := b.UDP.RawNetAddr()
			if destAddr == nil {
				b.Release()
				continue
			}
			n, err = w.PacketConnWrapper.WriteTo(b.Bytes(), destAddr)
		} else {
			n, err = w.PacketConnWrapper.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if w.Counter != nil {
			w.Counter.Add(int64(n))
		}
	}
	return nil
}

type NoisePacketWriter struct {
	buf.Writer
	noises      []*Noise
	firstWrite  bool
	UDPOverride net.Destination
	remoteAddr  net.Address
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		//Do not send Noise for dns requests(just to be safe)
		if w.UDPOverride.Port == 53 {
			return w.Writer.WriteMultiBuffer(mb)
		}
		var noise []byte
		var err error
		if w.remoteAddr.Family().IsDomain() {
			panic("impossible, remoteAddr is always IP")
		}
		for _, n := range w.noises {
			switch n.ApplyTo {
			case "ipv4":
				if w.remoteAddr.Family().IsIPv6() {
					continue
				}
			case "ipv6":
				if w.remoteAddr.Family().IsIPv4() {
					continue
				}
			case "ip":
			default:
				panic("unreachable, applyTo is ip/ipv4/ipv6")
			}
			//User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				//Random noise
				noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
					int64(n.LengthMax)))
			}
			if err != nil {
				return err
			}
			err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if err != nil {
				return err
			}

			if n.DelayMin != 0 || n.DelayMax != 0 {
				time.Sleep(time.Duration(crypto.RandBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond)
			}
		}

	}
	return w.Writer.WriteMultiBuffer(mb)
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.writer.Write(buff[:5+l])
				time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.writer.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}
	maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
