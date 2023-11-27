package netlink

import (
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type Handle struct {
	*netlink.Handle
}

func NewHandle(nlFamilies ...int) (*Handle, error) {
	h, err := netlink.NewHandle(nlFamilies...)
	if err != nil {
		return nil, err
	}
	return &Handle{h}, nil
}

func (h *Handle) WireGuardSetDevice(device *WireGuardDevice) (err error) {
	f, err := h.GenlFamilyGet(unix.WG_GENL_NAME)
	if err != nil {
		return err
	}

	req := nl.NewNetlinkRequest(int(f.ID), unix.NLM_F_ACK)
	req.AddData(&WireGuardSetDeviceHeader{})
	req.AddData(nl.NewRtAttr(unix.WGDEVICE_A_IFNAME, nl.ZeroTerminated(device.Device)))

	var flags uint32
	if device.Flags&WGDEVICE_HAS_PRIVATE_KEY != 0 {
		req.AddData(nl.NewRtAttr(unix.WGDEVICE_A_PRIVATE_KEY, device.PrivateKey[:]))
	}
	if device.Flags&WGDEVICE_HAS_LISTEN_PORT != 0 {
		req.AddData(nl.NewRtAttr(unix.WGDEVICE_A_LISTEN_PORT, nl.Uint16Attr(device.ListenPort)))
	}
	if device.Flags&WGDEVICE_HAS_FWMARK != 0 {
		req.AddData(nl.NewRtAttr(unix.WGDEVICE_A_FWMARK, nl.Uint32Attr(device.Fwmark)))
	}
	if device.Flags&WGDEVICE_REPLACE_PEERS != 0 {
		flags |= unix.WGDEVICE_F_REPLACE_PEERS
	}
	if flags > 0 {
		req.AddData(nl.NewRtAttr(unix.WGDEVICE_A_FLAGS, nl.Uint32Attr(flags)))
	}

	peers := nl.NewRtAttr(unix.WGDEVICE_A_PEERS|unix.NLA_F_NESTED, nil)
	for _, peer := range device.Peers {
		var flags uint32
		if peer.Flags&WGPEER_REMOVE_ME != 0 {
			flags |= unix.WGPEER_F_REMOVE_ME
		}
		if peer.Flags&WGPEER_REPLACE_ALLOWEDIPS != 0 {
			flags |= unix.WGPEER_F_REPLACE_ALLOWEDIPS
		}

		p := nl.NewRtAttr(unix.NLA_F_NESTED, nil)
		p.AddRtAttr(unix.WGPEER_A_PUBLIC_KEY, peer.PublicKey[:])
		if peer.Flags&WGPEER_HAS_PRESHARED_KEY != 0 {
			p.AddRtAttr(unix.WGPEER_A_PRESHARED_KEY, peer.PresharedKey[:])
		}
		p.AddRtAttr(unix.WGPEER_A_ENDPOINT, peer.EndpointAsSlice())
		if peer.Flags&WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL != 0 {
			p.AddRtAttr(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
				nl.Uint16Attr(peer.PersistentKeepaliveInterval))
		}

		if flags > 0 {
			p.AddRtAttr(unix.WGPEER_A_FLAGS, nl.Uint32Attr(flags))
		}

		as := nl.NewRtAttr(unix.WGPEER_A_ALLOWEDIPS|unix.NLA_F_NESTED, nil)
		for _, ip := range peer.AllowedIPs {
			var family uint16 = unix.AF_UNSPEC
			if ip.Addr().Is4() {
				family = unix.AF_INET
			}
			if ip.Addr().Is6() {
				family = unix.AF_INET6
			}

			a := nl.NewRtAttr(unix.NLA_F_NESTED, nil)
			a.AddRtAttr(unix.WGALLOWEDIP_A_FAMILY, nl.Uint16Attr(family))
			a.AddRtAttr(unix.WGALLOWEDIP_A_IPADDR, ip.Addr().AsSlice())
			a.AddRtAttr(unix.WGALLOWEDIP_A_CIDR_MASK, nl.Uint8Attr(uint8(ip.Bits())))

			as.AddChild(a)
		}
		if len(peer.AllowedIPs) > 0 {
			p.AddChild(as)
		}

		peers.AddChild(p)
	}
	if len(device.Peers) > 0 {
		req.AddData(peers)
	}

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}
