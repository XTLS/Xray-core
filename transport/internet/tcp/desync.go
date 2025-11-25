//go:build linux
// +build linux

package tcp

import (
	"net"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

var (
	desyncEnabled bool
	desyncOnce    sync.Once
)

func checkPermissions() bool {
	desyncOnce.Do(func() {
		if runtime.GOOS != "linux" {
			desyncEnabled = false
			return
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			desyncEnabled = false
			return
		}
		unix.Close(fd)
		desyncEnabled = true
	})
	return desyncEnabled
}

func performDesync(conn net.Conn, config *internet.DesyncConfig) error {
	if !checkPermissions() {
		return errors.New("CAP_NET_RAW capability is required for desync feature")
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not a TCP connection")
	}

	localAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("failed to get local address")
	}

	remoteAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("failed to get remote address")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return errors.New("failed to get raw connection").Base(err)
	}

	var (
		seq, ack uint32
		tcpWin   uint16
	)

	err = rawConn.Control(func(fd uintptr) {
		seq, ack, tcpWin = getTCPInfo(fd)
	})

	if err != nil {
		return errors.New("failed to get tcp info").Base(err)
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      uint8(config.Ttl),
		Protocol: layers.IPProtocolTCP,
		SrcIP:    localAddr.IP,
		DstIP:    remoteAddr.IP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(localAddr.Port),
		DstPort: layers.TCPPort(remoteAddr.Port),
		Seq:     seq,
		Ack:     ack,
		Window:  tcpWin,
		ACK:     true,
		PSH:     true,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer, gopacket.Payload(config.Payload)); err != nil {
		return errors.New("failed to serialize layers").Base(err)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return errors.New("failed to create raw socket").Base(err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{},
	}
	copy(addr.Addr[:], remoteAddr.IP.To4())

	if err := unix.Sendto(fd, buf.Bytes(), 0, &addr); err != nil {
		return errors.New("failed to send raw packet").Base(err)
	}

	return nil
}
func getTCPInfo(fd uintptr) (seq uint32, ack uint32, win uint16) {
	if runtime.GOOS != "linux" {
		return 1, 1, 8192
	}
	info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 1, 1, 8192
	}
	return info.Unacked, info.Rcv_ssthresh, uint16(info.Rcv_wnd)
}
