package netlink

import (
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

/*
struct wgdevice {
	char name[IFNAMSIZ];
	uint32_t ifindex;

	uint32_t flags;

	uint8_t public_key[WG_KEY_LEN];
	uint8_t private_key[WG_KEY_LEN];

	uint32_t fwmark;
	uint16_t listen_port;

	struct wgpeer *first_peer, *last_peer;
};
*/

// WireGuardDevice describes a WireGuard device.
type WireGuardDevice struct {
	Device     string
	Index      uint32
	Flags      uint32
	PublicKey  [32]byte
	PrivateKey [32]byte
	Fwmark     uint32
	ListenPort uint16
	Peers      []WireGuardPeer
}

/*
struct wgpeer {
	uint32_t flags;

	uint8_t public_key[WG_KEY_LEN];
	uint8_t preshared_key[WG_KEY_LEN];

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;

	struct timespec64 last_handshake_time;
	uint64_t rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

	struct wgallowedip *first_allowedip, *last_allowedip;
	struct wgpeer *next_peer;
};

struct wgallowedip {
	uint16_t family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	uint8_t cidr;
	struct wgallowedip *next_allowedip;
};
*/

// WireGuardPeer describes a WireGuard peer.
type WireGuardPeer struct {
	Flags                       uint32
	PublicKey                   [unix.WG_KEY_LEN]byte
	PresharedKey                [unix.WG_KEY_LEN]byte
	Endpoint                    netip.AddrPort
	LastHandshakeTime           time.Time
	RxBytes                     uint64
	TxBytes                     uint64
	PersistentKeepaliveInterval uint16
	AllowedIPs                  []netip.Prefix
}

func (p WireGuardPeer) EndpointAsSlice() []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, p.Endpoint.Port())
	port := binary.LittleEndian.Uint16(buf)
	if p.Endpoint.Addr().Is4() {
		out := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   port,
			Addr:   p.Endpoint.Addr().As4(),
		}
		return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&out)))[:]
	}
	out := unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Port:   port,
		Addr:   p.Endpoint.Addr().As16(),
	}
	return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&out)))[:]
}

/*
enum {
	WGDEVICE_REPLACE_PEERS = 1U << 0,
	WGDEVICE_HAS_PRIVATE_KEY = 1U << 1,
	WGDEVICE_HAS_PUBLIC_KEY = 1U << 2,
	WGDEVICE_HAS_LISTEN_PORT = 1U << 3,
	WGDEVICE_HAS_FWMARK = 1U << 4
};
*/

const (
	WGDEVICE_REPLACE_PEERS = 1 << iota
	WGDEVICE_HAS_PRIVATE_KEY
	WGDEVICE_HAS_PUBLIC_KEY
	WGDEVICE_HAS_LISTEN_PORT
	WGDEVICE_HAS_FWMARK
)

/*
enum {
	WGPEER_REMOVE_ME = 1U << 0,
	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
	WGPEER_HAS_PUBLIC_KEY = 1U << 2,
	WGPEER_HAS_PRESHARED_KEY = 1U << 3,
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4
};
*/

const (
	WGPEER_REMOVE_ME = 1 << iota
	WGPEER_REPLACE_ALLOWEDIPS
	WGPEER_HAS_PUBLIC_KEY
	WGPEER_HAS_PRESHARED_KEY
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL
)

var _ nl.NetlinkRequestData = &WireGuardSetDeviceHeader{}

type WireGuardSetDeviceHeader struct{}

func (w WireGuardSetDeviceHeader) Len() int {
	return unix.GENL_HDRLEN
}

func (w WireGuardSetDeviceHeader) Serialize() []byte {
	var header unix.Genlmsghdr
	header.Cmd = unix.WG_CMD_SET_DEVICE
	header.Version = unix.WG_GENL_VERSION
	return (*(*[unix.GENL_HDRLEN]byte)(unsafe.Pointer(&header)))[:]
}
