//go:build windows
// +build windows

package udp

import (
	"encoding/binary"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/sys/windows"
)

func RetrieveOriginalDest(oob []byte) net.Destination {
	dest := net.Destination{}
	port := binary.LittleEndian.Uint16(oob[:2])
	buf := buf.FromBytes(oob[2:])
	defer buf.Release()

	for !buf.IsEmpty() {
		cm := &windows.WSACMSGHDR{}
		len := make([]byte, unsafe.Sizeof(cm.Len))
		nRead, err := buf.Read(len)
		if err != nil {
			return dest
		}
		cm.Len = uintptr(binary.LittleEndian.Uint16(len))
		binary.Read(buf, binary.LittleEndian, &cm.Level)
		binary.Read(buf, binary.LittleEndian, &cm.Type)
		nRead += 8 // len cm.Level + cm.Type

		if cm.Type == windows.IP_PKTINFO {
			if cm.Level == windows.IPPROTO_IP { // IPv4
				pktinf := &windows.IN_PKTINFO{}
				binary.Read(buf, binary.LittleEndian, pktinf)
				return net.UDPDestination(net.IPAddress(pktinf.Addr[:]), net.Port(port))
			} else { // IPv6
				pktinfv6 := &windows.IN6_PKTINFO{}
				binary.Read(buf, binary.LittleEndian, pktinfv6)
				return net.UDPDestination(net.IPAddress(pktinfv6.Addr[:]), net.Port(port))
			}
		}
		buf.Advance(int32(cm.Len) - int32(nRead))
	}
	return dest
}

func ReadUDPMsg(conn *net.UDPConn, payload []byte, oob []byte) (int, int, int, *net.UDPAddr, error) {
	udpAddr, _ := net.ResolveUDPAddr(conn.LocalAddr().Network(), conn.LocalAddr().String())
	binary.LittleEndian.PutUint16(oob[:2], uint16(udpAddr.Port))
	n, oobn, flags, addr, err := conn.ReadMsgUDP(payload, oob[2:])
	return n, oobn + 2, flags, addr, err
}
