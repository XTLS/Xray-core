package masque

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func allocateAll(p *addressPool) []netip.Addr {
	var addrs []netip.Addr
	for {
		addr, ok := p.allocate()
		if !ok {
			return addrs
		}
		addrs = append(addrs, addr)
	}
}

func TestAddressPool(t *testing.T) {
	p, err := newAddressPool(netip.MustParsePrefix("10.0.0.1/29"))
	require.NoError(t, err)
	var want []netip.Addr
	for _, s := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		want = append(want, netip.MustParseAddr(s))
	}
	require.Equal(t, want, allocateAll(p))

	p.release(netip.MustParseAddr("10.0.0.4"))
	addr, ok := p.allocate()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("10.0.0.4"), addr)
	_, ok = p.allocate()
	require.False(t, ok)

	p, err = newAddressPool(netip.MustParsePrefix("fd00::1/126"))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::3")}, allocateAll(p))

	p, err = newAddressPool(netip.MustParsePrefix("10.0.0.2/30"))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, allocateAll(p))
}

func TestAddressPoolRejects(t *testing.T) {
	for _, s := range []string{
		"10.0.0.0/24",
		"10.0.0.255/24",
		"10.0.0.1/31",
		"10.0.0.1/32",
		"fd00::1/127",
		"fd00::1/128",
		"::ffff:10.0.0.1/120",
	} {
		_, err := newAddressPool(netip.MustParsePrefix(s))
		require.Error(t, err, s)
	}
}
