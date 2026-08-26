//go:build openbsd
// +build openbsd

package udp

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/unix"
)

func retrieveOriginalDestFromControlMessages(msgs []unix.SocketControlMessage) net.Destination {
	var ip []byte
	var port uint16
	var haveAddress bool
	var havePort bool

	for _, msg := range msgs {
		switch msg.Header.Level {
		case unix.IPPROTO_IP:
			switch msg.Header.Type {
			case unix.IP_RECVDSTADDR:
				if len(msg.Data) < 4 {
					continue
				}
				ip = append(ip[:0], msg.Data[:4]...)
				haveAddress = true
			case unix.IP_RECVDSTPORT:
				if len(msg.Data) < 2 {
					continue
				}
				port = binary.BigEndian.Uint16(msg.Data[:2])
				havePort = true
			}
		case unix.IPPROTO_IPV6:
			switch msg.Header.Type {
			case unix.IPV6_PKTINFO:
				// struct in6_pktinfo: the destination address is followed by
				// the interface index.
				if len(msg.Data) < 16 {
					continue
				}
				ip = append(ip[:0], msg.Data[:16]...)
				haveAddress = true
			case unix.IPV6_RECVDSTPORT:
				if len(msg.Data) < 2 {
					continue
				}
				port = binary.BigEndian.Uint16(msg.Data[:2])
				havePort = true
			}
		}
	}

	if !haveAddress || !havePort || port == 0 {
		return net.Destination{}
	}

	return net.UDPDestination(net.IPAddress(ip), net.Port(port))
}

func RetrieveOriginalDest(oob []byte) net.Destination {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return net.Destination{}
	}
	return retrieveOriginalDestFromControlMessages(msgs)
}

func ReadUDPMsg(conn *net.UDPConn, payload []byte, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return conn.ReadMsgUDP(payload, oob)
}
