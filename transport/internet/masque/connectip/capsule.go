/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

const (
	capsuleTypeDatagram           http3.CapsuleType = 0
	capsuleTypeAddressAssign      http3.CapsuleType = 1
	capsuleTypeAddressRequest     http3.CapsuleType = 2
	capsuleTypeRouteAdvertisement http3.CapsuleType = 3
)

const (
	maxAddressesPerCapsule = 8192
	maxRoutesPerCapsule    = 8192
)

type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

type AssignedAddress struct {
	RequestID AddressRequestID
	IPPrefix  netip.Prefix
}

func (a AssignedAddress) Rejected() bool {
	return a.IPPrefix == rejectedIPv4Prefix || a.IPPrefix == rejectedIPv6Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(uint64(a.RequestID)) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

type addressRequestCapsule struct {
	RequestIDs []AddressRequestID
	Prefixes   []netip.Prefix
}

func parseAddressAssignCapsule(r http3.CapsuleReader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for r.Remaining() > 0 {
		if len(assignedAddresses) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("%w: ADDRESS_ASSIGN capsule contains too many addresses (maximum %d)", errCapsuleLimit, maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: AddressRequestID(requestID), IPPrefix: prefix})
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func (c *addressAssignCapsule) append(b []byte) []byte {
	totalLen := 0
	for _, addr := range c.AssignedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressAssign))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.AssignedAddresses {
		b = quicvarint.Append(b, uint64(addr.RequestID))
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddressRequestCapsule(r http3.CapsuleReader) (*addressRequestCapsule, error) {
	if r.Remaining() == 0 {
		return nil, errors.New("ADDRESS_REQUEST capsule contains no addresses")
	}
	capsule := &addressRequestCapsule{}
	for r.Remaining() > 0 {
		if len(capsule.Prefixes) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("%w: ADDRESS_REQUEST capsule contains too many addresses (maximum %d)", errCapsuleLimit, maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		if requestID == 0 {
			return nil, errors.New("ADDRESS_REQUEST capsule contains a zero request ID")
		}
		capsule.RequestIDs = append(capsule.RequestIDs, AddressRequestID(requestID))
		capsule.Prefixes = append(capsule.Prefixes, prefix)
	}
	return capsule, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for i, p := range c.Prefixes {
		totalLen += quicvarint.Len(uint64(c.RequestIDs[i])) + 1 + p.Addr().BitLen()/8 + 1
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for i, p := range c.Prefixes {
		b = quicvarint.Append(b, uint64(c.RequestIDs[i]))
		if p.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, p.Addr().AsSlice()...)
		b = append(b, byte(p.Bits()))
	}
	return b
}

func parseAddress(r io.Reader) (requestID uint64, prefix netip.Prefix, _ error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return 0, netip.Prefix{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix = netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return 0, netip.Prefix{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return requestID, prefix, nil
}

type routeAdvertisementCapsule struct {
	IPAddressRanges []IPRoute
}

type IPRoute struct {
	StartIP    netip.Addr
	EndIP      netip.Addr
	IPProtocol uint8
}

func (r IPRoute) len() int { return 1 + r.StartIP.BitLen()/8 + r.EndIP.BitLen()/8 + 1 }

func (r IPRoute) Prefixes() []netip.Prefix { return rangeToPrefixes(r.StartIP, r.EndIP) }

func parseRouteAdvertisementCapsule(r http3.CapsuleReader) (*routeAdvertisementCapsule, error) {
	var ranges []IPRoute
	for r.Remaining() > 0 {
		if len(ranges) >= maxRoutesPerCapsule {
			return nil, fmt.Errorf("%w: ROUTE_ADVERTISEMENT capsule contains too many routes (maximum %d)", errCapsuleLimit, maxRoutesPerCapsule)
		}
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			if err := checkRouteOrder(ranges[len(ranges)-1], ipRange); err != nil {
				return nil, err
			}
		}
		ranges = append(ranges, ipRange)
	}
	return &routeAdvertisementCapsule{IPAddressRanges: ranges}, nil
}

func (r IPRoute) validate() error {
	if !r.StartIP.IsValid() || !r.EndIP.IsValid() || r.StartIP.Zone() != "" || r.EndIP.Zone() != "" {
		return fmt.Errorf("invalid IP address range %s-%s", r.StartIP, r.EndIP)
	}
	if r.StartIP.Is4() != r.EndIP.Is4() {
		return fmt.Errorf("IP address range %s-%s mixes IP versions", r.StartIP, r.EndIP)
	}
	if r.StartIP.Compare(r.EndIP) > 0 {
		return fmt.Errorf("start IP %s is greater than end IP %s", r.StartIP, r.EndIP)
	}
	return nil
}

func checkRouteOrder(a, b IPRoute) error {
	switch cmp.Or(
		cmp.Compare(a.StartIP.BitLen(), b.StartIP.BitLen()),
		cmp.Compare(a.IPProtocol, b.IPProtocol),
	) {
	case 1:
		return fmt.Errorf("routes are not ordered by IP version and IP protocol: %s-%s (protocol %d) precedes %s-%s (protocol %d)",
			a.StartIP, a.EndIP, a.IPProtocol, b.StartIP, b.EndIP, b.IPProtocol)
	case 0:
		if a.EndIP.Compare(b.StartIP) >= 0 {
			return fmt.Errorf("IP address ranges %s-%s and %s-%s (protocol %d) overlap or are not in ascending order",
				a.StartIP, a.EndIP, b.StartIP, b.EndIP, b.IPProtocol)
		}
	}
	return nil
}

func (c *routeAdvertisementCapsule) append(b []byte) []byte {
	var totalLen int
	for _, ipRange := range c.IPAddressRanges {
		totalLen += ipRange.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeRouteAdvertisement))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, ipRange := range c.IPAddressRanges {
		if ipRange.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, ipRange.StartIP.AsSlice()...)
		b = append(b, ipRange.EndIP.AsSlice()...)
		b = append(b, ipRange.IPProtocol)
	}
	return b
}

func parseIPAddressRange(r io.Reader) (IPRoute, error) {
	var ipVersion uint8
	if err := binary.Read(r, binary.LittleEndian, &ipVersion); err != nil {
		return IPRoute{}, err
	}

	var startIP, endIP netip.Addr
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom4(start)
		endIP = netip.AddrFrom4(end)
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom16(start)
		endIP = netip.AddrFrom16(end)
	default:
		return IPRoute{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	if startIP.Compare(endIP) > 0 {
		return IPRoute{}, errors.New("start IP is greater than end IP")
	}

	var ipProtocol uint8
	if err := binary.Read(r, binary.LittleEndian, &ipProtocol); err != nil {
		return IPRoute{}, err
	}
	return IPRoute{
		StartIP:    startIP,
		EndIP:      endIP,
		IPProtocol: ipProtocol,
	}, nil
}
