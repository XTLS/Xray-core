//go:build !linux && !android && !darwin && !ios

package icmp

import (
	stdnet "net"
	"os"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func openEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	var errs []interface{}
	for _, candidate := range socketCandidates(netProto, dstIP) {
		conn, err := listenEchoSocket(candidate)
		if err == nil {
			return &Socket{
				Network:               candidate.network,
				RemoteAddr:            candidate.remoteAddr,
				Conn:                  conn,
				AcceptLocalIdentifier: candidate.acceptLocalIdentifier,
			}, nil
		}
		errs = append(errs, candidate.network, ": ", err, "; ")
	}
	return nil, errors.New(errs...)
}

func socketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	switch netProto {
	case header.IPv4ProtocolNumber:
		ip := stdnet.IP(dstIP.AsSlice())
		return []socketConfig{
			{network: "udp4", controllerNetwork: "udp4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.UDPAddr{IP: ip}},
			{network: "ip4:icmp", controllerNetwork: "ip4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	case header.IPv6ProtocolNumber:
		ip := stdnet.IP(dstIP.AsSlice())
		return []socketConfig{
			{network: "udp6", controllerNetwork: "udp6", listenAddr: "::", remoteAddr: &stdnet.UDPAddr{IP: ip}},
			{network: "ip6:ipv6-icmp", controllerNetwork: "ip6", listenAddr: "::", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	default:
		return nil
	}
}

func listenEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
	if IsDatagramNetwork(config.network) {
		return listenDatagramEchoSocket(config)
	}

	conn, err := stdnet.ListenPacket(config.network, config.listenAddr)
	if err != nil {
		return nil, err
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("icmp packet conn does not expose syscall conn")
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := applyRawSocketControllers(config.controllerNetwork, config.remoteAddr.String(), rawConn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func listenDatagramEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
	family := syscall.AF_INET
	proto := syscall.IPPROTO_ICMP
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}

	switch config.network {
	case "udp4":
	case "udp6":
		family = syscall.AF_INET6
		proto = syscall.IPPROTO_ICMPV6
		sa = &syscall.SockaddrInet6{}
	default:
		return nil, errors.New("unsupported datagram icmp network: ", config.network)
	}

	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}

	file := os.NewFile(uintptr(fd), "icmp datagram")
	conn, err := stdnet.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("icmp datagram conn does not expose syscall conn")
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := applyRawSocketControllers(config.controllerNetwork, config.remoteAddr.String(), rawConn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
