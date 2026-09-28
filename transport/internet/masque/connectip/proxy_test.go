/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func dialHTTP3(t *testing.T, addr string) *http3.ClientConn {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(
		ctx,
		addr,
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true, InitialPacketSize: 1350, DisablePathMTUDiscovery: true},
	)
	require.NoError(t, err)
	t.Cleanup(func() { qconn.CloseWithError(0, "") })
	return (&http3.Transport{EnableDatagrams: true}).NewClientConn(qconn)
}

func setupConns(t *testing.T) (client, server *Conn) {
	t.Helper()

	p := &Proxy{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	proxyURL := fmt.Sprintf("https://%s/connect-ip", conn.LocalAddr())
	connChan := make(chan *Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/connect-ip", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		mreq, err := ParseProxyRequest(r)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, mreq)
		if assert.NoError(t, err) {
			connChan <- conn
		}
	})
	s := http3.Server{
		Handler:         mux,
		Addr:            ":0",
		EnableDatagrams: true,
		TLSConfig:       tlsConf,
	}
	go func() { s.Serve(conn) }()
	t.Cleanup(func() { s.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := NewRequest(ctx, proxyURL)
	require.NoError(t, err)
	req.Header().Set("Authorization", "Bearer token")
	client, rsp, err := NewClientConn(dialHTTP3(t, conn.LocalAddr().String())).Dial(req)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.Equal(t, http.StatusOK, rsp.StatusCode)

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	case server = <-connChan:
	}
	t.Cleanup(func() { server.Close() })
	return client, server
}

func TestAddressAssignment(t *testing.T) {
	client, server := setupConns(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := server.ReceiveAddressAssignment(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pref1 := netip.MustParsePrefix("1.1.1.0/24")
	pref2 := netip.MustParsePrefix("2001:db8::/64")
	require.NoError(t, client.AssignAddresses([]netip.Prefix{pref1, pref2}))
	assigned, err := server.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Equal(t, []AssignedAddress{{IPPrefix: pref1}, {IPPrefix: pref2}}, assigned)

	require.NoError(t, client.AssignAddresses([]netip.Prefix{}))
	assigned, err = server.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Empty(t, assigned)
}

func TestRejectingAddressRequestKeepsPeerUnrestricted(t *testing.T) {
	client, server := setupConns(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	clientAddr := netip.MustParsePrefix("192.0.2.2/32")
	require.NoError(t, server.AssignAddresses([]netip.Prefix{clientAddr}))
	_, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)

	_, err = server.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")})
	require.NoError(t, err)
	req, err := client.ReceiveAddressRequest(ctx)
	require.NoError(t, err)
	require.NoError(t, req.Respond([]netip.Prefix{{}}, nil))
	assigned, err := server.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Len(t, assigned, 1)
	require.True(t, assigned[0].Rejected())

	packet := ipv4Packet(64, 17, netip.MustParseAddr("203.0.113.9"), clientAddr.Addr(), nil, []byte("foobar"))
	_, err = server.WritePacket(slices.Clone(packet))
	require.NoError(t, err)
	received := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1500)
		if n, err := client.ReadPacket(b); err == nil {
			received <- b[:n]
		}
	}()
	select {
	case b := <-received:
		require.Equal(t, packet[20:], b[20:])
	case <-ctx.Done():
		t.Fatal("packet was not received")
	}
}

func TestRejectingAddressRequestWithdrawsAssignment(t *testing.T) {
	client, server := setupConns(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	clientAddr := netip.MustParsePrefix("192.0.2.2/32")
	dst := netip.MustParseAddr("198.51.100.1")
	require.NoError(t, server.AssignAddresses([]netip.Prefix{clientAddr}))
	require.NoError(t, server.AdvertiseRoute([]IPRoute{{StartIP: dst, EndIP: dst}}))
	_, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)

	received := make(chan []byte, 4)
	go func() {
		b := make([]byte, 1500)
		for {
			n, err := server.ReadPacket(b)
			if err != nil {
				return
			}
			received <- slices.Clone(b[20:n])
		}
	}()
	send := func(payload string) {
		_, err := client.WritePacket(ipv4Packet(64, 17, clientAddr.Addr(), dst, nil, []byte(payload)))
		require.NoError(t, err)
	}

	send("assigned")
	select {
	case b := <-received:
		require.Equal(t, "assigned", string(b))
	case <-ctx.Done():
		t.Fatal("packet from the assigned address was not received")
	}

	_, err = client.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")})
	require.NoError(t, err)
	req, err := server.ReceiveAddressRequest(ctx)
	require.NoError(t, err)
	require.NoError(t, req.Respond([]netip.Prefix{{}}, nil))
	assigned, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Len(t, assigned, 1)
	require.True(t, assigned[0].Rejected())

	send("withdrawn")
	select {
	case b := <-received:
		t.Fatalf("packet from a withdrawn address was received: %q", b)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRouteAdvertisement(t *testing.T) {
	client, server := setupConns(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := server.Routes(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	require.ErrorContains(t,
		client.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.2"), EndIP: netip.MustParseAddr("1.1.1.1"), IPProtocol: 42},
		}),
		"connect-ip: invalid route 0: start IP 1.1.1.2 is greater than end IP 1.1.1.1",
	)

	require.NoError(t, client.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("2.2.2.2"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 24},
	}))
	routes, err := server.Routes(ctx)
	require.NoError(t, err)
	require.Equal(t, []IPRoute{
		{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("2.2.2.2"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 24},
	}, routes)

	require.NoError(t, client.AdvertiseRoute([]IPRoute{}))
	routes, err = server.Routes(ctx)
	require.NoError(t, err)
	require.Empty(t, routes)
}

func TestTTLs(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		client, server := setupConns(t)
		require.NoError(t, server.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")}))
		require.NoError(t, server.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
		}))

		src, dst := netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("8.8.8.8")
		icmp, err := client.WritePacket(ipv4Packet(1, 0, src, dst, nil, nil))
		require.NoError(t, err)
		require.Empty(t, icmp)

		icmp, err = client.WritePacket(ipv4Packet(42, 0, src, dst, nil, nil))
		require.NoError(t, err)
		require.Empty(t, icmp)

		receivedPacket := make([]byte, 1500)
		n, err := server.ReadPacket(receivedPacket)
		require.NoError(t, err)
		receivedPacket = receivedPacket[:n]

		receivedHdr, err := ipv4.ParseHeader(receivedPacket)
		require.NoError(t, err)
		require.Equal(t, uint16(receivedHdr.Checksum), calculateIPv4Checksum(receivedPacket[:ipv4.HeaderLen]))
		require.Equal(t, 41, receivedHdr.TTL)
	})

	t.Run("IPv6", func(t *testing.T) {
		client, server := setupConns(t)
		require.NoError(t, server.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}))
		require.NoError(t, server.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		}))

		packetHopLimit1 := []byte{
			0x60, 0x00, 0x00, 0x00,
			0x00, 0x00,
			0x00, 0x01,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
		}
		icmp, err := client.WritePacket(packetHopLimit1)
		require.NoError(t, err)
		require.Empty(t, icmp)

		packet := []byte{
			0x60, 0x00, 0x00, 0x00,
			0x00, 0x00,
			0x00, 0x2A,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
		}
		icmp, err = client.WritePacket(packet)
		require.NoError(t, err)
		require.Empty(t, icmp)

		receivedPacket := make([]byte, 1500)
		n, err := server.ReadPacket(receivedPacket)
		require.NoError(t, err)
		receivedPacket = receivedPacket[:n]

		receivedHdr, err := ipv6.ParseHeader(receivedPacket)
		require.NoError(t, err)
		require.Equal(t, 41, receivedHdr.HopLimit)
	})
}

func TestMaxPacketSizeOverQUIC(t *testing.T) {
	client, server := setupConns(t)
	require.NoError(t, server.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")},
	}))

	size := client.MaxPacketSize()
	require.Greater(t, size, 1200)
	require.Less(t, size, 1350)

	icmp, err := client.WritePacket(ipv4Packet(64, 17, testSrc4, testDst4, nil, make([]byte, size-ipv4.HeaderLen)))
	require.NoError(t, err)
	require.Nil(t, icmp)
	type readResult struct {
		n   int
		err error
	}
	received := make(chan readResult, 1)
	go func() {
		n, err := server.ReadPacket(make([]byte, 1500))
		received <- readResult{n, err}
	}()
	select {
	case r := <-received:
		require.NoError(t, r.err)
		require.Equal(t, size, r.n)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	icmp, err = client.WritePacket(ipv4Packet(64, 17, testSrc4, testDst4, nil, make([]byte, size+1-ipv4.HeaderLen)))
	require.NoError(t, err)
	require.NotNil(t, icmp)
	require.Equal(t, uint16(size), binary.BigEndian.Uint16(icmp[ipv4.HeaderLen+6:]))
}

func TestClosing(t *testing.T) {
	ipv6Packet := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x2A,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
	}

	client, server := setupConns(t)
	routeErrChan := make(chan error, 1)
	prefixErrChan := make(chan error, 1)
	go func() {
		_, err := server.Routes(context.Background())
		routeErrChan <- err
	}()
	go func() {
		_, err := server.ReceiveAddressAssignment(context.Background())
		prefixErrChan <- err
	}()

	require.NoError(t, client.Close())
	_, err := client.ReceiveAddressAssignment(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.False(t, closeErr.Remote)
	_, err = client.Routes(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)
	require.ErrorIs(t,
		client.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}),
		net.ErrClosed,
	)
	require.ErrorIs(t,
		client.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.0"), EndIP: netip.MustParseAddr("1.1.1.1"), IPProtocol: 42},
		}),
		net.ErrClosed,
	)
	_, err = client.ReadPacket([]byte{0})
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = client.WritePacket(ipv6Packet)
	require.ErrorIs(t, err, net.ErrClosed)

	select {
	case err := <-routeErrChan:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-prefixErrChan:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, err = server.ReadPacket([]byte{0})
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = server.WritePacket(ipv6Packet)
	require.ErrorIs(t, err, net.ErrClosed)
}
