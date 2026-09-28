/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
)

var (
	rejectedIPv4Prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
	rejectedIPv6Prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 128)
)

type AddressRequestID uint64

type AddressRequest struct {
	Prefixes []netip.Prefix

	conn      *Conn
	requested *addressRequestCapsule
	responded *atomic.Bool
}

func newAddressRequest(conn *Conn, requested *addressRequestCapsule) *AddressRequest {
	return &AddressRequest{
		Prefixes:  slices.Clone(requested.Prefixes),
		conn:      conn,
		requested: requested,
		responded: &atomic.Bool{},
	}
}

func (r *AddressRequest) Respond(assignments, additional []netip.Prefix) error {
	if r.conn == nil {
		return errors.New("connect-ip: invalid address request")
	}
	if len(assignments) != len(r.requested.RequestIDs) {
		return fmt.Errorf(
			"connect-ip: expected %d address assignments, got %d",
			len(r.requested.RequestIDs),
			len(assignments),
		)
	}
	capsule := &addressAssignCapsule{
		AssignedAddresses: make([]AssignedAddress, 0, len(assignments)+len(additional)),
	}
	var zeroPrefix netip.Prefix
	for i, p := range assignments {
		if p == zeroPrefix {
			if r.requested.Prefixes[i].Addr().Is4() {
				p = rejectedIPv4Prefix
			} else {
				p = rejectedIPv6Prefix
			}
		} else if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("connect-ip: invalid assigned prefix %d: %s", i, p)
		}
		capsule.AssignedAddresses = append(
			capsule.AssignedAddresses,
			AssignedAddress{RequestID: r.requested.RequestIDs[i], IPPrefix: p},
		)
	}
	for i, p := range additional {
		if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("connect-ip: invalid additional prefix %d: %s", i, p)
		}
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	if !r.responded.CompareAndSwap(false, true) {
		return errors.New("connect-ip: address request already answered")
	}
	restrictPeer := slices.ContainsFunc(capsule.AssignedAddresses, func(a AssignedAddress) bool { return !a.Rejected() })
	if err := r.conn.sendAddressAssignment(capsule, restrictPeer); err != nil {
		r.responded.Store(false)
		return err
	}
	return nil
}
