package wireguard

import (
	"encoding/binary"
	goerrors "errors"
	"net"
	"net/netip"
	"unsafe"

	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/sys/unix"
)

const (
	gsoControlSize = 24 // room for unix.CmsgSpace(2)

	// maxGSOSegments is the kernel's limit of datagrams in one UDP_SEGMENT send.
	maxGSOSegments = 64
	// A UDP_SEGMENT send must fit in one IP packet before it is split.
	maxGSOPayload4 = 1<<16 - 1 - 20 - 8
	maxGSOPayload6 = 1<<16 - 1 - 8
)

// gsoConn returns the UDP socket under c if the kernel takes UDP_SEGMENT on it
// (Linux 4.18+), and the counter for what is sent through it.
func gsoConn(c net.PacketConn) (msgWriter, stats.Counter) {
	var wc stats.Counter
	if pc, ok := c.(*PacketCounterConnection); ok {
		c, wc = pc.PacketConn, pc.WriteCounter
	}
	udp, ok := c.(*net.UDPConn)
	if !ok {
		return nil, nil
	}
	rc, err := udp.SyscallConn()
	if err != nil {
		return nil, nil
	}
	var gso bool
	_ = rc.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = err == nil
	})
	if !gso {
		return nil, nil
	}
	return udp, wc
}

// sendGSO sends runs of equal-sized datagrams, of which only the last may be
// shorter, as one UDP_SEGMENT message each, and returns how many of bufs went
// out. Like wireguard-go, it copies a run into the spare room of its first
// buffer, which is the rest of a device message buffer.
func sendGSO(c msgWriter, bufs [][]byte, addr netip.AddrPort, wc stats.Counter) (int, error) {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	maxLen := maxGSOPayload6
	if addr.Addr().Is4() {
		maxLen = maxGSOPayload4
	}
	var oob [gsoControlSize]byte
	for i := 0; i < len(bufs); {
		msg, size := bufs[i], len(bufs[i])
		j := i + 1
		for ; j < len(bufs) && j-i < maxGSOSegments; j++ {
			n := len(bufs[j])
			if n > size || len(msg)+n > maxLen || n > cap(msg)-len(msg) {
				break
			}
			msg = append(msg, bufs[j]...)
			if n < size {
				j++
				break
			}
		}
		var control []byte
		if j-i > 1 {
			control = setGSOSize(oob[:], size)
		}
		if _, _, err := c.WriteMsgUDPAddrPort(msg, control, addr); err != nil {
			return i, err
		}
		if wc != nil {
			wc.Add(int64(len(msg)))
		}
		i = j
	}
	return len(bufs), nil
}

// setGSOSize writes a UDP_SEGMENT control message to oob and returns it.
func setGSOSize(oob []byte, size int) []byte {
	oob = oob[:unix.CmsgSpace(2)]
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(size))
	return oob
}

// gsoFailed reports whether a send failed because the route cannot take
// UDP_SEGMENT: EIO without checksum offload, EMSGSIZE (EINVAL on older
// kernels) when a segment is larger than the path MTU, where a plain send
// would be fragmented.
func gsoFailed(err error) bool {
	return goerrors.Is(err, unix.EIO) || goerrors.Is(err, unix.EMSGSIZE) || goerrors.Is(err, unix.EINVAL)
}
