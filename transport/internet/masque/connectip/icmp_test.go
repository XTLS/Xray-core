/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestICMPTooLargeIPv4(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.1")
	dst := netip.MustParseAddr("8.8.8.8")
	origHdr := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: 60,
		TTL:      64,
		Protocol: 6,
		Src:      src.AsSlice(),
		Dst:      dst.AsSlice(),
	}
	origBytes, err := origHdr.Marshal()
	require.NoError(t, err)
	data, err := composeICMPTooLargePacket(origBytes, 1200)
	require.NoError(t, err)

	hdr, err := ipv4.ParseHeader(data)
	require.NoError(t, err)
	require.Equal(t, 4, hdr.Version)
	require.Equal(t, ipProtoICMP, hdr.Protocol)
	require.Equal(t, dst.String(), hdr.Src.String())
	require.Equal(t, src.String(), hdr.Dst.String())
	require.Equal(t, uint16(hdr.Checksum), calculateIPv4Checksum(data[:ipv4.HeaderLen]))
	icmpMsg, err := icmp.ParseMessage(ipProtoICMP, data[ipv4.HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, ipv4.ICMPTypeDestinationUnreachable, icmpMsg.Type)
	require.Equal(t, 4, icmpMsg.Code)
	require.Equal(t, uint16(1200), binary.BigEndian.Uint16(data[ipv4.HeaderLen+6:]))
	require.Equal(t, origBytes, data[ipv4.HeaderLen+8:])
}

func TestICMPTooLargeIPv4Options(t *testing.T) {
	options := []byte{0x94, 0x04, 0x00, 0x00}
	orig := ipv4Packet(64, 6, netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("8.8.8.8"), options, make([]byte, 20))
	data, err := composeICMPTooLargePacket(orig, 1200)
	require.NoError(t, err)
	require.Equal(t, orig[:ipv4.HeaderLen+len(options)+8], data[ipv4.HeaderLen+8:])
}

func TestICMPTooLargeIPv6(t *testing.T) {
	const mtu = 1337
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("1:2:3:4::5")
	orig := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x2a,
	}
	orig = append(orig, src.AsSlice()...)
	orig = append(orig, dst.AsSlice()...)
	orig = append(orig, []byte("foobar")...)
	data, err := composeICMPTooLargePacket(orig, mtu)
	require.NoError(t, err)

	hdr, err := ipv6.ParseHeader(data)
	require.NoError(t, err)
	require.Equal(t, 6, hdr.Version)
	require.Equal(t, ipProtoICMPv6, hdr.NextHeader)
	require.Equal(t, dst.String(), hdr.Src.String())
	require.Equal(t, src.String(), hdr.Dst.String())
	icmpMsg, err := icmp.ParseMessage(ipProtoICMPv6, data[ipv6.HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, ipv6.ICMPTypePacketTooBig, icmpMsg.Type)
	icmpBody, ok := icmpMsg.Body.(*icmp.PacketTooBig)
	require.True(t, ok)
	require.Equal(t, mtu, icmpBody.MTU)
	require.Equal(t, orig, icmpBody.Data)
}

func TestICMPTooLargeMinimumMTU(t *testing.T) {
	ipv4Orig := ipv4Packet(64, 6, testSrc4, testDst4, nil, make([]byte, 100))
	ipv6Orig := ipv6Packet(64, 6, testSrc6, testDst6, make([]byte, 1300))
	for _, tc := range []struct {
		name     string
		packet   []byte
		mtu      int
		tooSmall bool
	}{
		{"IPv4 minimum", ipv4Orig, 68, false},
		{"IPv4 below minimum", ipv4Orig, 67, true},
		{"IPv4 negative", ipv4Orig, -1, true},
		{"IPv6 minimum", ipv6Orig, 1280, false},
		{"IPv6 below minimum", ipv6Orig, 1279, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := composeICMPTooLargePacket(tc.packet, tc.mtu)
			if tc.tooSmall {
				require.ErrorIs(t, err, ErrMTUTooSmall)
				require.Nil(t, data)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, data)
		})
	}
}

func TestICMPFailures(t *testing.T) {
	t.Run("empty packet", func(t *testing.T) {
		_, err := composeICMPTooLargePacket([]byte{}, 1)
		require.EqualError(t, err, "connect-ip: empty packet")
	})

	t.Run("too short IPv4 header", func(t *testing.T) {
		origHdr := &ipv4.Header{
			Version:  4,
			Len:      ipv4.HeaderLen,
			TotalLen: 60,
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(5, 6, 7, 8),
		}
		data, err := origHdr.Marshal()
		require.NoError(t, err)
		_, err = composeICMPTooLargePacket(data[:ipv4.HeaderLen-1], 1)
		require.EqualError(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("too short IPv6 header", func(t *testing.T) {
		data := []byte{
			0x60, 0x00, 0x00, 0x00,
			0x00, 0x00,
			0x00, 0x40,
		}
		data = append(data, net.ParseIP("2001:db8::1").To16()...)
		data = append(data, net.ParseIP("2001:db8::2").To16()...)
		_, err := composeICMPTooLargePacket(data[:ipv6.HeaderLen-1], 1)
		require.EqualError(t, err, "connect-ip: IPv6 packet too short")
	})

	t.Run("unknown IP version", func(t *testing.T) {
		data := []byte{
			0x30, 0x00, 0x00, 0x00,
		}
		_, err := composeICMPTooLargePacket(data, 1)
		require.EqualError(t, err, "connect-ip: unknown IP version: 3")
	})
}
