package wireguard

import (
	"encoding/hex"
	"net/netip"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func (p *PeerConfig) AsAccount() (protocol.Account, error) {
	pub, err := ParseKey(p.PublicKey)
	if err != nil {
		return nil, err
	}

	allowedIPs := make([]netip.Prefix, 0, len(p.AllowedIps))
	for _, ip := range p.AllowedIps {
		p, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, err
		}
		allowedIPs = append(allowedIPs, p)
	}

	return &MemoryAccount{
		Pub:          *pub,
		AllowedIPs:   allowedIPs,
		PreSharedKey: p.PreSharedKey,
		KeepAlive:    p.KeepAlive,
	}, nil
}

type MemoryAccount struct {
	Pub          [32]byte
	AllowedIPs   []netip.Prefix
	PreSharedKey string
	KeepAlive    string
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Pub == b.Pub
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	allowedIPs := make([]string, 0, len(a.AllowedIPs))
	for _, ip := range a.AllowedIPs {
		allowedIPs = append(allowedIPs, ip.String())
	}

	return &PeerConfig{
		PublicKey:    hex.EncodeToString(a.Pub[:]),
		AllowedIps:   allowedIPs,
		PreSharedKey: a.PreSharedKey,
		KeepAlive:    a.KeepAlive,
	}
}
