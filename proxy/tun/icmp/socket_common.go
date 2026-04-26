package icmp

import (
	stdnet "net"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Socket struct {
	Network               string
	RemoteAddr            stdnet.Addr
	Conn                  stdnet.PacketConn
	AcceptLocalIdentifier bool
}

type socketConfig struct {
	network               string
	controllerNetwork     string
	listenAddr            string
	remoteAddr            stdnet.Addr
	acceptLocalIdentifier bool
}

func OpenEchoSocket(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) (*Socket, error) {
	return openEchoSocket(netProto, dstIP)
}

func (s *Socket) ReplyIdentifier() (uint16, bool) {
	if s == nil || !s.AcceptLocalIdentifier {
		return 0, false
	}
	return DatagramEchoIdentifier(s.Conn.LocalAddr())
}

func (s *Socket) ShouldSkipSyntheticReply(srcIP stdnet.IP) (bool, error) {
	return shouldSkipSyntheticReply(s, srcIP)
}

func applyRawSocketControllers(network, address string, rawConn syscall.RawConn) error {
	internet.ControllersLock.Lock()
	controllers := append([]func(string, string, syscall.RawConn) error(nil), internet.Controllers...)
	internet.ControllersLock.Unlock()

	for _, ctl := range controllers {
		if err := ctl(network, address, rawConn); err != nil {
			return err
		}
	}

	return nil
}

func openEchoSocketWithCandidates(candidates []socketConfig, permissionHint string, permissionError func(error) bool) (*Socket, error) {
	if len(candidates) == 0 {
		return nil, errors.New("unsupported icmp network protocol")
	}

	var errs []interface{}
	allPermissionDenied := permissionHint != "" && permissionError != nil
	for _, candidate := range candidates {
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
		if allPermissionDenied && !permissionError(err) {
			allPermissionDenied = false
		}
	}
	if allPermissionDenied {
		errs = append(errs, permissionHint)
	}
	return nil, errors.New(errs...)
}

func rawSocketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address) []socketConfig {
	ip := stdnet.IP(dstIP.AsSlice())
	switch netProto {
	case header.IPv4ProtocolNumber:
		return []socketConfig{
			{network: "ip4:icmp", controllerNetwork: "ip4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	case header.IPv6ProtocolNumber:
		return []socketConfig{
			{network: "ip6:ipv6-icmp", controllerNetwork: "ip6", listenAddr: "::", remoteAddr: &stdnet.IPAddr{IP: ip}},
		}
	default:
		return nil
	}
}

func datagramSocketCandidates(netProto tcpip.NetworkProtocolNumber, dstIP tcpip.Address, acceptLocalIdentifier bool) []socketConfig {
	ip := stdnet.IP(dstIP.AsSlice())
	switch netProto {
	case header.IPv4ProtocolNumber:
		return []socketConfig{
			{network: "udp4", controllerNetwork: "udp4", listenAddr: "0.0.0.0", remoteAddr: &stdnet.UDPAddr{IP: ip}, acceptLocalIdentifier: acceptLocalIdentifier},
		}
	case header.IPv6ProtocolNumber:
		return []socketConfig{
			{network: "udp6", controllerNetwork: "udp6", listenAddr: "::", remoteAddr: &stdnet.UDPAddr{IP: ip}, acceptLocalIdentifier: acceptLocalIdentifier},
		}
	default:
		return nil
	}
}

func listenRawEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
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

func isPermissionErrorWithFragments(err error, fragments ...string) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	for _, fragment := range fragments {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}
