/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipv4MinMTU = 68
	ipv6MinMTU = 1280
)

var ErrMTUTooSmall = errors.New("connect-ip: tunnel MTU below the minimum link MTU")

func composeICMPTooLargePacket(b []byte, mtu int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("connect-ip: empty packet")
	}

	var icmpMessage *icmp.Message
	var psh []byte
	switch v := ipVersion(b); v {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, errors.New("connect-ip: IPv4 packet too short")
		}
		if mtu < ipv4MinMTU {
			return nil, fmt.Errorf("%w: %d bytes", ErrMTUTooSmall, mtu)
		}
		icmpMessage = &icmp.Message{
			Type: ipv4.ICMPTypeDestinationUnreachable,
			Code: 4,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), max(ipv4.HeaderLen, int(b[0]&0x0f)<<2)+8)],
			},
		}
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, errors.New("connect-ip: IPv6 packet too short")
		}
		if mtu < ipv6MinMTU {
			return nil, fmt.Errorf("%w: %d bytes", ErrMTUTooSmall, mtu)
		}
		icmpMessage = &icmp.Message{
			Type: ipv6.ICMPTypePacketTooBig,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), 1232)],
			},
		}
		psh = icmp.IPv6PseudoHeader(b[24:40], b[8:24])
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP version: %d", v)
	}

	icmp, err := icmpMessage.Marshal(psh)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to marshal ICMP message: %w", err)
	}

	if ipVersion(b) == 4 {
		var header [ipv4.HeaderLen]byte
		header[0] = 4<<4 | ipv4.HeaderLen>>2
		ipLen := ipv4.HeaderLen + len(icmp)
		binary.BigEndian.PutUint16(header[2:4], uint16(ipLen))
		header[8] = 64
		header[9] = 1
		copy(header[12:16], b[16:20])
		copy(header[16:20], b[12:16])
		binary.BigEndian.PutUint16(header[10:12], calculateIPv4Checksum(header[:]))
		return append(header[:], icmp...), nil
	}

	var header [ipv6.HeaderLen]byte
	header[0] = 6 << 4
	binary.BigEndian.PutUint16(header[4:6], uint16(len(icmp)))
	header[6] = 58
	header[7] = 64
	copy(header[8:24], b[24:40])
	copy(header[24:40], b[8:24])
	return append(header[:], icmp...), nil
}
