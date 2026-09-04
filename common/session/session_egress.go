package session

import (
	gonet "net"

	"github.com/xtls/xray-core/common/net"
)

func destinationFromStdAddr(addr gonet.Addr) (net.Destination, bool) {
	switch addr := addr.(type) {
	case *gonet.TCPAddr:
		if addr == nil {
			return net.Destination{}, false
		}
		return net.TCPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), true
	case *gonet.UDPAddr:
		if addr == nil {
			return net.Destination{}, false
		}
		return net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), true
	default:
		return net.Destination{}, false
	}
}

func (o *Outbound) SetEgressSource(source net.Destination) {
	if o == nil || !source.IsValid() {
		return
	}
	o.egressSourceMu.Lock()
	o.EgressSource = source
	callback := o.OnEgressSource
	o.egressSourceMu.Unlock()
	if callback != nil {
		callback(source)
	}
}

func (o *Outbound) SetEgressSourceFromAddr(addr gonet.Addr) {
	source, ok := destinationFromStdAddr(addr)
	if !ok {
		return
	}
	o.SetEgressSource(source)
}

func (o *Outbound) EgressSourceSnapshot() net.Destination {
	if o == nil {
		return net.Destination{}
	}
	o.egressSourceMu.RLock()
	defer o.egressSourceMu.RUnlock()
	return o.EgressSource
}

func SetOutboundEgressSource(outbounds []*Outbound, source net.Destination) {
	if !source.IsValid() {
		return
	}
	for _, outbound := range outbounds {
		if outbound != nil {
			outbound.SetEgressSource(source)
		}
	}
}

func SetOutboundEgressSourceFromAddr(outbounds []*Outbound, addr gonet.Addr) {
	source, ok := destinationFromStdAddr(addr)
	if !ok {
		return
	}
	SetOutboundEgressSource(outbounds, source)
}
