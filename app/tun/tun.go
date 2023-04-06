package tun

import (
	"context"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-tun"
	sing_common "github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ranges"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	features_tun "github.com/xtls/xray-core/features/tun"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*Config))
	}))
}

var TunInitializer features_tun.Interface = (*Tun)(nil)

type Tun struct {
	ctx                    context.Context
	dispatcher             routing.Dispatcher
	logger                 logger.ContextLogger
	tunOptions             tun.Options
	stack                  string
	endpointIndependentNat bool
	udpTimeout             int64
	tunIf                  tun.Tun
	tunStack               tun.Stack
	networkMonitor         tun.NetworkUpdateMonitor
	interfaceMonitor       tun.DefaultInterfaceMonitor
	packageManager         tun.PackageManager
	interfaceFinder        *myInterfaceFinder
}

func New(ctx context.Context, config *Config) (*Tun, error) {
	instance := core.MustFromContext(ctx)
	tunInterface := &Tun{
		ctx:                    ctx,
		dispatcher:             instance.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		logger:                 singbridge.NewLogger(newError),
		stack:                  config.Stack,
		endpointIndependentNat: config.EndpointIndependentNat,
		udpTimeout:             int64(5 * time.Minute.Seconds()),
		interfaceFinder:        new(myInterfaceFinder),
	}
	networkUpdateMonitor, err := tun.NewNetworkUpdateMonitor(tunInterface)
	if err != nil {
		return nil, err
	}
	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkUpdateMonitor, tun.DefaultInterfaceMonitorOptions{
		OverrideAndroidVPN: config.OverrideAndroidVpn,
	})
	if err != nil {
		return nil, err
	}
	defaultInterfaceMonitor.RegisterCallback(tunInterface.notifyNetworkUpdate)
	if config.AutoDetectInterface {
		networkUpdateMonitor.RegisterCallback(tunInterface.interfaceFinder.update)
		const useInterfaceName = runtime.GOOS == "linux" || runtime.GOOS == "android"
		bindFunc := control.BindToInterfaceFunc(tunInterface.interfaceFinder, func(network string, address string) (interfaceName string, interfaceIndex int) {
			remoteAddr := M.ParseSocksaddr(address).Addr
			if useInterfaceName {
				return defaultInterfaceMonitor.DefaultInterfaceName(remoteAddr), -1
			} else {
				return "", defaultInterfaceMonitor.DefaultInterfaceIndex(remoteAddr)
			}
		})
		internet.UseAlternativeSystemDialer(nil)
		internet.RegisterDialerController(bindFunc)
		internet.RegisterListenerController(bindFunc)
	}
	if runtime.GOOS == "android" {
		packageManage, err := tun.NewPackageManager(tunInterface)
		if err != nil {
			return nil, err
		}
		tunInterface.packageManager = packageManage
	}
	tunInterface.networkMonitor = networkUpdateMonitor
	tunInterface.interfaceMonitor = defaultInterfaceMonitor
	tunName := config.InterfaceName
	if tunName == "" {
		tunName = tun.CalculateInterfaceName("")
	}
	tunMTU := config.Mtu
	if tunMTU == 0 {
		tunMTU = 9000
	}
	includeUID := uidToRange(config.IncludeUid)
	if len(config.IncludeUidRange) > 0 {
		var err error
		includeUID, err = parseRange(includeUID, config.IncludeUidRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(config.ExcludeUid)
	if len(config.ExcludeUidRange) > 0 {
		var err error
		excludeUID, err = parseRange(excludeUID, config.ExcludeUidRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}
	if config.UdpTimeout != 0 {
		tunInterface.udpTimeout = config.UdpTimeout
	}
	tunInterface.tunOptions = tun.Options{
		Name:              tunName,
		Inet4Address:      sing_common.Map(config.Inet4Address, netip.MustParsePrefix),
		Inet6Address:      sing_common.Map(config.Inet6Address, netip.MustParsePrefix),
		MTU:               tunMTU,
		AutoRoute:         config.AutoRoute,
		StrictRoute:       config.StrictRoute,
		Inet4RouteAddress: sing_common.Map(config.Inet4RouteAddress, netip.MustParsePrefix),
		Inet6RouteAddress: sing_common.Map(config.Inet6RouteAddress, netip.MustParsePrefix),
		IncludeUID:        includeUID,
		ExcludeUID:        excludeUID,
		IncludeAndroidUser: sing_common.Map(config.IncludeAndroidUser, func(it int32) int {
			return int(it)
		}),
		IncludePackage:   config.IncludePackage,
		ExcludePackage:   config.ExcludePackage,
		InterfaceMonitor: defaultInterfaceMonitor,
		TableIndex:       2022,
	}
	return tunInterface, nil
}

func (t *Tun) Type() interface{} {
	return features_tun.InterfaceType()
}

func (t *Tun) Start() error {
	err := t.interfaceMonitor.Start()
	if err != nil {
		return err
	}
	err = t.networkMonitor.Start()
	if err != nil {
		return err
	}
	if runtime.GOOS == "android" {
		err = t.packageManager.Start()
		if err != nil {
			return err
		}
		t.tunOptions.BuildAndroidRules(t.packageManager, t)
	}
	tunIf, err := tun.New(t.tunOptions)
	if err != nil {
		return E.Cause(err, "configure tun interface")
	}
	t.tunIf = tunIf
	t.tunStack, err = tun.NewStack(t.stack, tun.StackOptions{
		Context:                t.ctx,
		Tun:                    tunIf,
		MTU:                    t.tunOptions.MTU,
		Name:                   t.tunOptions.Name,
		Inet4Address:           t.tunOptions.Inet4Address,
		Inet6Address:           t.tunOptions.Inet6Address,
		EndpointIndependentNat: t.endpointIndependentNat,
		UDPTimeout:             t.udpTimeout,
		Handler:                t,
		Logger:                 t.logger,
	})
	if err != nil {
		return err
	}
	err = t.tunStack.Start()
	if err != nil {
		return err
	}
	t.logger.Info("tun started at ", t.tunOptions.Name)
	return nil
}

func (t *Tun) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	sid := session.NewID()
	ctx = session.ContextWithID(ctx, sid)
	t.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: net.DestinationFromAddr(metadata.Source.TCPAddr()),
		Conn:   conn,
	})
	wConn := singbridge.NewConn(conn)
	_ = t.dispatcher.DispatchLink(ctx, singbridge.ToDestination(metadata.Destination, net.Network_TCP), &transport.Link{
		Reader: wConn,
		Writer: wConn,
	})
	conn.Close()
	return nil
}

func (t *Tun) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	sid := session.NewID()
	ctx = session.ContextWithID(ctx, sid)
	t.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: net.DestinationFromAddr(metadata.Source.UDPAddr()),
	})
	pc := &PacketConn{conn}
	_ = t.dispatcher.DispatchLink(ctx, singbridge.ToDestination(metadata.Destination, net.Network_UDP), &transport.Link{
		Reader: pc,
		Writer: pc,
	})
	conn.Close()
	return nil
}

func (t *Tun) Close() error {
	return sing_common.Close(
		t.packageManager,
		t.interfaceMonitor,
		t.networkMonitor,
		t.tunStack,
		t.tunIf,
	)
}

func (t *Tun) OnPackagesUpdated(packages int, sharedUsers int) {
	t.logger.Info("updated packages list: ", packages, " packages, ", sharedUsers, " shared users")
}

func (t *Tun) NewError(ctx context.Context, err error) {
}

func (t *Tun) notifyNetworkUpdate(int) error {
	if runtime.GOOS == "android" {
		var vpnStatus string
		if t.interfaceMonitor.AndroidVPNEnabled() {
			vpnStatus = "enabled"
		} else {
			vpnStatus = "disabled"
		}
		t.logger.Info("updated default interface ", t.interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified()), ", index ", t.interfaceMonitor.DefaultInterfaceIndex(netip.IPv4Unspecified()), ", vpn ", vpnStatus)
	} else {
		t.logger.Info("updated default interface ", t.interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified()), ", index ", t.interfaceMonitor.DefaultInterfaceIndex(netip.IPv4Unspecified()))
	}
	return nil
}

func uidToRange(uidList []uint32) []ranges.Range[uint32] {
	return sing_common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uint32(uid))
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}
