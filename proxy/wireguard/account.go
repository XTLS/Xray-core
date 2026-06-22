package wireguard

import (
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount is the runtime representation of a WireGuard peer credential.
// It is produced by PeerConfig.AsAccount and consumed by the UserManager methods
// on Server (AddUser / RemoveUser / GetUser / GetUsers / GetUsersCount).
type MemoryAccount struct {
	PublicKey    string
	PreSharedKey string
	AllowedIPs   []string
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(other protocol.Account) bool {
	b, ok := other.(*MemoryAccount)
	return ok && a.PublicKey == b.PublicKey
}

// ToProto implements protocol.Account.
func (a *MemoryAccount) ToProto() proto.Message {
	return &PeerConfig{
		PublicKey:    a.PublicKey,
		PreSharedKey: a.PreSharedKey,
		AllowedIps:   a.AllowedIPs,
	}
}

// AsAccount implements protocol.AsAccount so that PeerConfig can be used as a
// typed account in an AddUserOperation. API callers set the @type field to
// "xray.proxy.wireguard.PeerConfig".
func (p *PeerConfig) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		PublicKey:    p.PublicKey,
		PreSharedKey: p.PreSharedKey,
		AllowedIPs:   p.AllowedIps,
	}, nil
}

// buildPeerIPC returns a WireGuard IPC string that adds or updates a single peer.
func buildPeerIPC(a *MemoryAccount) string {
	var b strings.Builder
	b.WriteString("public_key=" + a.PublicKey + "\n")
	if a.PreSharedKey != "" {
		b.WriteString("preshared_key=" + a.PreSharedKey + "\n")
	}
	for _, ip := range a.AllowedIPs {
		b.WriteString("allowed_ip=" + ip + "\n")
	}
	return b.String()
}

// buildRemovePeerIPC returns a WireGuard IPC string that removes a peer.
func buildRemovePeerIPC(publicKey string) string {
	return "public_key=" + publicKey + "\nremove=true\n"
}

// parseFirstAddr extracts the host address from a CIDR string or plain address
// (e.g. "10.0.0.2/32" → 10.0.0.2, "fd00::1" → fd00::1).
func parseFirstAddr(cidr string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.ParseAddr(cidr)
	}
	return prefix.Addr(), nil
}
