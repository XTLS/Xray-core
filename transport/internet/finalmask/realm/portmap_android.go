package realm

import (
	"context"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/httpu"
	"github.com/huin/goupnp/ssdp"
	"github.com/libp2p/go-nat"
	"github.com/wlynxg/anet"
	"github.com/xtls/xray-core/common/errors"
)

// Android 11+ denies apps the netlink calls behind net.Interfaces (golang/go#40569),
// which goupnp and go-nat both need, so fall back to UPnP over anet-listed addresses.
func discoverGateway(ctx context.Context) (nat.NAT, error) {
	gateway, err := nat.DiscoverGateway(ctx)
	if err == nil || ctx.Err() != nil {
		return gateway, err
	}
	return discoverUPnP(ctx)
}

func discoverUPnP(ctx context.Context) (nat.NAT, error) {
	addrs, err := localIPv4MCastAddrs()
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no multicast IPv4 address")
	}
	clients := make([]httpu.ClientInterface, 0, len(addrs))
	for _, addr := range addrs {
		c, err := httpu.NewHTTPUClientAddr(addr)
		if err != nil {
			return nil, errors.New("failed to create HTTPU client for ", addr).Base(err)
		}
		defer c.Close()
		clients = append(clients, c)
	}
	hc := httpu.NewMultiClient(clients)

	for _, search := range []struct{ target, ig string }{
		{internetgateway1.URN_WANConnectionDevice_1, "IG1"},
		{internetgateway2.URN_WANConnectionDevice_2, "IG2"},
	} {
		responses, err := ssdp.SSDPRawSearchCtx(ctx, hc, search.target, 2, 3)
		if err != nil {
			return nil, errors.New("SSDP search failed").Base(err)
		}
		for _, response := range responses {
			loc, err := response.Location()
			if err != nil {
				continue
			}
			internalAddr := net.ParseIP(response.Header.Get(httpu.LocalAddressHeader))
			if internalAddr == nil {
				continue
			}
			root, err := goupnp.DeviceByURLCtx(ctx, loc)
			if err != nil {
				continue
			}
			if gateway := newUPnPGateway(ctx, root, search.ig, internalAddr); gateway != nil {
				return gateway, nil
			}
		}
	}
	return nil, nat.ErrNoNATFound
}

// localIPv4MCastAddrs mirrors goupnp's address selection, but lists interfaces via anet.
func localIPv4MCastAddrs() ([]string, error) {
	ifaces, err := anet.Interfaces()
	if err != nil {
		return nil, errors.New("failed to list interfaces").Base(err)
	}
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		ifaceAddrs, err := anet.InterfaceAddrsByInterface(&iface)
		if err != nil {
			return nil, errors.New("failed to list addresses of ", iface.Name).Base(err)
		}
		for _, addr := range ifaceAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				addrs = append(addrs, ipNet.IP.String())
			}
		}
	}
	return addrs, nil
}

type upnpClient interface {
	GetNATRSIPStatusCtx(ctx context.Context) (bool, bool, error)
	GetExternalIPAddress() (string, error)
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
}

func newUPnPGateway(ctx context.Context, root *goupnp.RootDevice, ig string, internalAddr net.IP) *upnpGateway {
	var gateway *upnpGateway
	root.Device.VisitServices(func(srv *goupnp.Service) {
		if gateway != nil || ctx.Err() != nil {
			return
		}
		sc := goupnp.ServiceClient{SOAPClient: srv.NewSOAPClient(), RootDevice: root, Service: srv}
		var client upnpClient
		var typ string
		switch srv.ServiceType {
		case internetgateway2.URN_WANIPConnection_1:
			client, typ = &internetgateway2.WANIPConnection1{ServiceClient: sc}, "IP1"
		case internetgateway2.URN_WANIPConnection_2:
			client, typ = &internetgateway2.WANIPConnection2{ServiceClient: sc}, "IP2"
		case internetgateway2.URN_WANPPPConnection_1:
			client, typ = &internetgateway2.WANPPPConnection1{ServiceClient: sc}, "PPP1"
		default:
			return
		}
		if _, isNat, err := client.GetNATRSIPStatusCtx(ctx); err == nil && isNat {
			gateway = &upnpGateway{
				client:       client,
				typ:          "UPNP (" + ig + "-" + typ + ")",
				root:         root,
				internalAddr: internalAddr,
				ports:        make(map[int]int),
			}
		}
	})
	return gateway
}

// upnpGateway is go-nat's UPnP NAT with the internal address taken from SSDP
// discovery instead of net.Interfaces.
type upnpGateway struct {
	client       upnpClient
	typ          string
	root         *goupnp.RootDevice
	internalAddr net.IP
	ports        map[int]int
}

func (g *upnpGateway) Type() string {
	return g.typ
}

func (g *upnpGateway) GetDeviceAddress() (net.IP, error) {
	addr, err := net.ResolveUDPAddr("udp4", g.root.URLBase.Host)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

func (g *upnpGateway) GetExternalAddress() (net.IP, error) {
	s, err := g.client.GetExternalIPAddress()
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, nat.ErrNoExternalAddress
	}
	return ip, nil
}

func (g *upnpGateway) GetInternalAddress() (net.IP, error) {
	return g.internalAddr, nil
}

func (g *upnpGateway) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, timeout time.Duration) (int, error) {
	protocol = strings.ToUpper(protocol)
	lease := uint32(timeout / time.Second)
	if externalPort := g.ports[internalPort]; externalPort > 0 {
		err := g.client.AddPortMappingCtx(ctx, "", uint16(externalPort), protocol, uint16(internalPort), g.internalAddr.String(), true, description, lease)
		if err == nil {
			return externalPort, nil
		}
	}
	var err error
	for range 3 {
		externalPort := rand.IntN(65535-10000) + 10000
		err = g.client.AddPortMappingCtx(ctx, "", uint16(externalPort), protocol, uint16(internalPort), g.internalAddr.String(), true, description, lease)
		if err == nil {
			g.ports[internalPort] = externalPort
			return externalPort, nil
		}
	}
	return 0, err
}

func (g *upnpGateway) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	externalPort := g.ports[internalPort]
	if externalPort == 0 {
		return nil
	}
	delete(g.ports, internalPort)
	return g.client.DeletePortMappingCtx(ctx, "", uint16(externalPort), strings.ToUpper(protocol))
}
