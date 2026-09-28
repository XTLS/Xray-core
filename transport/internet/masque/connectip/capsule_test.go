/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func newCapsuleReader(t *testing.T, typ http3.CapsuleType, payload []byte) http3.CapsuleReader {
	t.Helper()

	data := quicvarint.Append(nil, uint64(typ))
	data = quicvarint.Append(data, uint64(len(payload)))
	data = append(data, payload...)
	parsedType, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
	require.NoError(t, err)
	require.Equal(t, typ, parsedType)
	return cr
}

func testIncompleteCapsule(t *testing.T, data []byte, parse func(http3.CapsuleReader) error) {
	t.Helper()

	r := bytes.NewReader(data)
	_, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.NoError(t, parse(cr))
	require.Zero(t, r.Len())
	for i := range data {
		_, cr, err := http3.NewCapsuleParser(bytes.NewReader(data[:i])).Next()
		if err != nil {
			if i == 0 {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
			continue
		}
		require.ErrorIs(t, parse(cr), io.ErrUnexpectedEOF)
	}
}

func testCapsuleEntryLimit[T any](t *testing.T, typ http3.CapsuleType, limit int, entry func(i int) []byte, parse func(http3.CapsuleReader) (*T, error)) {
	t.Helper()
	var payload []byte
	for i := range limit {
		payload = append(payload, entry(i)...)
	}
	r := newCapsuleReader(t, typ, payload)
	_, err := parse(r)
	require.NoError(t, err)
	require.Zero(t, r.Remaining())

	data := quicvarint.Append(nil, uint64(typ))
	data = quicvarint.Append(data, uint64(len(payload)+1))
	_, r, err = http3.NewCapsuleParser(bytes.NewReader(append(data, payload...))).Next()
	require.NoError(t, err)
	_, err = parse(r)
	require.ErrorContains(t, err, "too many")
	require.Equal(t, int64(1), r.Remaining())
}

func TestParseAddressAssignCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337)
	addr1 = append(addr1, 4)
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)
	addr2 := quicvarint.Append(nil, 1338)
	addr2 = append(addr2, 6)
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128)

	data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2)))
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	capsule, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.AssignedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestParseAddressAssignCapsuleLimit(t *testing.T) {
	entry := []byte{1, 4, 192, 0, 2, 1, 32}
	testCapsuleEntryLimit(t, capsuleTypeAddressAssign, maxAddressesPerCapsule, func(int) []byte { return entry }, parseAddressAssignCapsule)
}

func TestAssignedAddressRejected(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/32", "::/128"} {
		require.True(t, (AssignedAddress{RequestID: 1, IPPrefix: netip.MustParsePrefix(prefix)}).Rejected())
	}
	for _, prefix := range []string{"0.0.0.0/0", "0.0.0.0/31", "::/0", "::/127", "192.0.2.1/32", "2001:db8::1/128"} {
		require.False(t, (AssignedAddress{RequestID: 1, IPPrefix: netip.MustParsePrefix(prefix)}).Rejected())
	}
	require.False(t, (AssignedAddress{}).Rejected())
}

func TestWriteAddressAssignCapsule(t *testing.T) {
	c := &addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	parsed, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressAssignCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressAssign, func(r http3.CapsuleReader) error {
		_, err := parseAddressAssignCapsule(r)
		return err
	})
}

func testParseAddressCapsuleInvalid(t *testing.T, typ http3.CapsuleType, f func(r http3.CapsuleReader) error) {
	t.Run("invalid IP version", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)
		addr1 = append(addr1, 5)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32)
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "invalid IP version: 5")
	})

	t.Run("invalid prefix length", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)
		addr1 = append(addr1, 4)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 33)
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "prefix length 33 exceeds IP address length (32)")
	})

	t.Run("lower bits not covered by prefix length are not all zero", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)
		addr1 = append(addr1, 4)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 28)
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "lower bits not covered by prefix length are not all zero")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		var data []byte
		switch typ {
		case capsuleTypeAddressAssign:
			data = (&addressAssignCapsule{
				AssignedAddresses: []AssignedAddress{
					{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.4/32")},
					{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
				},
			}).append(nil)
		case capsuleTypeAddressRequest:
			data = (&addressRequestCapsule{
				RequestIDs: []AddressRequestID{1337, 1338},
				Prefixes:   []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32"), netip.MustParsePrefix("2001:db8::1/128")},
			}).append(nil)
		default:
			t.Fatalf("unexpected capsule type: %d", typ)
		}

		testIncompleteCapsule(t, data, f)
	})
}

func TestParseAddressRequestCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337)
	addr1 = append(addr1, 4)
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)
	addr2 := quicvarint.Append(nil, 1338)
	addr2 = append(addr2, 6)
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128)
	data := quicvarint.Append(nil, uint64(capsuleTypeAddressRequest))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2)))
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	capsule, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, []AddressRequestID{1337, 1338}, capsule.RequestIDs)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24"), netip.MustParsePrefix("2001:db8::1/128")}, capsule.Prefixes)
	require.Zero(t, r.Len())
}

func TestParseAddressRequestCapsuleLimit(t *testing.T) {
	entry := []byte{1, 4, 192, 0, 2, 1, 32}
	testCapsuleEntryLimit(t, capsuleTypeAddressRequest, maxAddressesPerCapsule, func(int) []byte { return entry }, parseAddressRequestCapsule)
}

func TestWriteAddressRequestCapsule(t *testing.T) {
	c := &addressRequestCapsule{
		RequestIDs: []AddressRequestID{1337, 1338},
		Prefixes:   []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24"), netip.MustParsePrefix("2001:db8::1/128")},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	parsed, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressRequestCapsuleInvalid(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		_, err := parseAddressRequestCapsule(newCapsuleReader(t, capsuleTypeAddressRequest, nil))
		require.ErrorContains(t, err, "contains no addresses")
	})
	t.Run("zero request ID", func(t *testing.T) {
		_, err := parseAddressRequestCapsule(newCapsuleReader(t, capsuleTypeAddressRequest, []byte{0, 4, 192, 0, 2, 1, 32}))
		require.ErrorContains(t, err, "zero request ID")
	})
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressRequest, func(r http3.CapsuleReader) error {
		_, err := parseAddressRequestCapsule(r)
		return err
	})
}

func TestParseRouteAdvertisementCapsule(t *testing.T) {
	iprange1 := []byte{4}
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...)
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
	iprange1 = append(iprange1, 13)
	iprange2 := []byte{6}
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...)
	iprange2 = append(iprange2, 37)

	data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
	data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2)))
	data = append(data, iprange1...)
	data = append(data, iprange2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	capsule, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
		capsule.IPAddressRanges,
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.2.3.4")),
		capsule.IPAddressRanges[0].Prefixes(),
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::100")),
		capsule.IPAddressRanges[1].Prefixes(),
	)
	require.Zero(t, r.Len())
}

func TestParseRouteAdvertisementCapsuleLimit(t *testing.T) {
	entry := func(i int) []byte { return []byte{4, 10, 0, byte(i >> 8), byte(i), 10, 0, byte(i >> 8), byte(i), 0} }
	testCapsuleEntryLimit(t, capsuleTypeRouteAdvertisement, maxRoutesPerCapsule, entry, parseRouteAdvertisementCapsule)
}

func TestWriteRouteAdvertisementCapsule(t *testing.T) {
	c := &routeAdvertisementCapsule{
		IPAddressRanges: []IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	parsed, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseRouteAdvertisementCapsuleInvalid(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		iprange1 := []byte{5}
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...)
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 2}).AsSlice()...)
		iprange1 = append(iprange1, 13)
		_, err := parseRouteAdvertisementCapsule(newCapsuleReader(t, capsuleTypeRouteAdvertisement, iprange1))
		require.ErrorContains(t, err, "invalid IP version: 5")
	})

	t.Run("start IP is greater than end IP", func(t *testing.T) {
		iprange1 := []byte{4}
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...)
		iprange1 = append(iprange1, 13)
		_, err := parseRouteAdvertisementCapsule(newCapsuleReader(t, capsuleTypeRouteAdvertisement, iprange1))
		require.ErrorContains(t, err, "start IP is greater than end IP")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		data := (&routeAdvertisementCapsule{
			IPAddressRanges: []IPRoute{
				{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("2.2.2.2"), IPProtocol: 13},
				{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
			},
		}).append(nil)

		testIncompleteCapsule(t, data, func(r http3.CapsuleReader) error {
			_, err := parseRouteAdvertisementCapsule(r)
			return err
		})
	})
}

var (
	route4a  = IPRoute{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.9")}
	route4b  = IPRoute{StartIP: netip.MustParseAddr("10.0.0.10"), EndIP: netip.MustParseAddr("10.0.0.20")}
	route4ab = IPRoute{StartIP: netip.MustParseAddr("10.0.0.9"), EndIP: netip.MustParseAddr("10.0.0.20")}
	route6   = IPRoute{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff")}
)

func withProtocol(r IPRoute, proto uint8) IPRoute {
	r.IPProtocol = proto
	return r
}

var routeOrderTests = []struct {
	name   string
	routes []IPRoute
	err    string
}{
	{name: "empty"},
	{name: "adjacent ranges", routes: []IPRoute{route4a, route4b}},
	{name: "IPv4 before IPv6 with a lower IP protocol", routes: []IPRoute{withProtocol(route4a, 17), route6}},
	{name: "same range for different IP protocols", routes: []IPRoute{withProtocol(route4a, 6), withProtocol(route4a, 17)}},
	{name: "IP protocol order before address order", routes: []IPRoute{withProtocol(route4b, 6), withProtocol(route4a, 17)}},
	{name: "IPv6 before IPv4", routes: []IPRoute{route6, route4a}, err: "not ordered by IP version and IP protocol"},
	{name: "descending IP protocols", routes: []IPRoute{withProtocol(route4a, 17), withProtocol(route4b, 6)}, err: "not ordered by IP version and IP protocol"},
	{name: "descending ranges", routes: []IPRoute{route4b, route4a}, err: "overlap or are not in ascending order"},
	{name: "overlapping ranges", routes: []IPRoute{route4a, route4ab}, err: "overlap or are not in ascending order"},
	{name: "duplicate range", routes: []IPRoute{route6, route6}, err: "overlap or are not in ascending order"},
}

func TestParseRouteAdvertisementCapsuleOrder(t *testing.T) {
	for _, tc := range routeOrderTests {
		t.Run(tc.name, func(t *testing.T) {
			data := (&routeAdvertisementCapsule{IPAddressRanges: tc.routes}).append(nil)
			_, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
			require.NoError(t, err)
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.routes, capsule.IPAddressRanges)
		})
	}
}

func TestAdvertiseRouteValidation(t *testing.T) {
	tests := []struct {
		name   string
		routes []IPRoute
		err    string
	}{
		{name: "invalid start IP", routes: []IPRoute{{EndIP: route4a.EndIP}}, err: "invalid IP address range"},
		{name: "invalid end IP", routes: []IPRoute{{StartIP: route4a.StartIP}}, err: "invalid IP address range"},
		{
			name:   "IPv6 zone",
			routes: []IPRoute{{StartIP: netip.MustParseAddr("fe80::1%eth0"), EndIP: netip.MustParseAddr("fe80::2%eth0")}},
			err:    "invalid IP address range",
		},
		{name: "mixed IP versions", routes: []IPRoute{{StartIP: route4a.StartIP, EndIP: route6.EndIP}}, err: "mixes IP versions"},
		{
			name:   "IPv4 and IPv4-mapped IPv6",
			routes: []IPRoute{{StartIP: netip.MustParseAddr("10.0.0.1"), EndIP: netip.MustParseAddr("::ffff:10.0.0.2")}},
			err:    "mixes IP versions",
		},
		{name: "start after end", routes: []IPRoute{route4a, {StartIP: route4b.EndIP, EndIP: route4b.StartIP}}, err: "invalid route 1: start IP 10.0.0.20 is greater than end IP 10.0.0.10"},
	}
	tests = append(tests, routeOrderTests...)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := newProxiedConn(&mockStream{})
			t.Cleanup(func() { conn.Close() })
			err := conn.AdvertiseRoute(tc.routes)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				conn.mu.Lock()
				defer conn.mu.Unlock()
				require.Empty(t, conn.queuedWrites)
				require.Nil(t, conn.localRoutes)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestReceiveMisorderedRouteAdvertisement(t *testing.T) {
	toRead := make(chan []byte, 1)
	conn := newProxiedConn(&mockStream{toRead: toRead})
	t.Cleanup(func() { conn.Close() })

	toRead <- (&routeAdvertisementCapsule{IPAddressRanges: []IPRoute{route6, route4a}}).append(nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := conn.Routes(ctx)
	require.ErrorIs(t, err, net.ErrClosed)
}
