/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddressRequests(t *testing.T) {
	client, server := setupConns(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("::/64"),
	}
	ids, err := client.RequestAddresses(prefixes)
	require.NoError(t, err)
	require.Equal(t, []AddressRequestID{1, 2, 3}, ids)
	req, err := server.ReceiveAddressRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, prefixes, req.Prefixes)

	assignments := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), {}, {}}
	additional := []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}
	require.NoError(t, req.Respond(assignments, additional))
	received, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Len(t, received, 4)
	require.Equal(t, AssignedAddress{RequestID: ids[0], IPPrefix: assignments[0]}, received[0])
	require.Equal(t, ids[1], received[1].RequestID)
	require.True(t, received[1].Rejected())
	require.Equal(t, ids[2], received[2].RequestID)
	require.True(t, received[2].Rejected())
	require.Equal(t, AssignedAddress{IPPrefix: additional[0]}, received[3])

	ids, err = client.RequestAddresses(prefixes[:1])
	require.NoError(t, err)
	require.Equal(t, []AddressRequestID{4}, ids)
}

func TestAddressRequestValidation(t *testing.T) {
	conn := newProxiedConn(&mockStream{})
	defer conn.Close()

	for _, prefixes := range [][]netip.Prefix{
		nil,
		{{}},
		{netip.MustParsePrefix("192.0.2.1/24")},
		{netip.MustParsePrefix("2001:db8::1/64")},
	} {
		ids, err := conn.RequestAddresses(prefixes)
		require.Error(t, err)
		require.Nil(t, ids)
	}
}

func TestAddressResponseValidation(t *testing.T) {
	conn := newProxiedConn(&mockStream{})
	defer conn.Close()

	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
	req := newAddressRequest(conn, &addressRequestCapsule{RequestIDs: []AddressRequestID{1}, Prefixes: prefixes})
	require.ErrorContains(t, (&AddressRequest{}).Respond(nil, nil), "invalid address request")
	require.ErrorContains(t, req.Respond(nil, nil), "expected 1 address assignments")
	require.ErrorContains(t, req.Respond(prefixes, []netip.Prefix{{}}), "invalid additional prefix")
	require.ErrorContains(t,
		req.Respond([]netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, nil),
		"invalid assigned prefix",
	)

	copied := *req
	require.NoError(t, req.Respond(prefixes, nil))
	require.ErrorContains(t, copied.Respond(prefixes, nil), "already answered")
}
