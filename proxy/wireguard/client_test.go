package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/curve25519"
)

type testDNS struct {
	fail atomic.Bool
	ips  []net.IP
}

func (*testDNS) Type() interface{} { return dns.ClientType() }
func (*testDNS) Start() error      { return nil }
func (*testDNS) Close() error      { return nil }
func (d *testDNS) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	if d.fail.Load() {
		return nil, 0, errors.New("lookup failed")
	}
	return d.ips, 600, nil
}

func testKey(t *testing.T) (priv, pub string) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k[:]), hex.EncodeToString(p)
}

func newTestClient(t *testing.T, endpoint string, d *testDNS) *Handler {
	t.Helper()
	priv, _ := testKey(t)
	_, peerPub := testKey(t)
	tun, tnet, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, true)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		conf: &DeviceConfig{
			SecretKey: priv,
			Peers:     []*PeerConfig{{PublicKey: peerPub, Endpoint: endpoint, AllowedIps: []string{"0.0.0.0/0"}}},
		},
		dns:            d,
		streamSettings: &internet.MemoryStreamConfig{},
		tun:            tun,
		tnet:           tnet,
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// The bind socket must come up for an endpoint that only Xray's DNS knows.
func TestClientEndpointResolvedByXrayDNS(t *testing.T) {
	h := newTestClient(t, "wg.test:51820", &testDNS{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	if err := h.init(context.Background()); err != nil {
		t.Fatal(err)
	}
}
