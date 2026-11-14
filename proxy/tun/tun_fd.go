//go:build linux

package tun

import (
	"encoding/binary"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// vnetSize is the size of the virtio_net_hdr that a tun with IFF_VNET_HDR has in front of every packet,
// unless it was told another one
const vnetSize = 10

// fdTun reads and writes the packets of a tun that is a file descriptor
type fdTun struct {
	fd int
	// file is what packets are read from: a read waits in the poller of the runtime and ends when file is closed
	file *os.File
	// vnet is the size of the virtio_net_hdr in front of every packet, zero if the tun has none.
	// With it the system does not split what it sends to the tun and takes what is not split from it
	vnet int
	// raw is file for ReadParts, readv what it calls when there may be a packet, iovecs where that reads to:
	// header, which takes the virtio_net_hdr, and the parts. read and readErr are what came of it
	raw     syscall.RawConn
	readv   func(fd uintptr) bool
	header  [packetRoom]byte
	iovecs  []unix.Iovec
	read    int
	readErr error

	writeLock sync.RWMutex
	closed    bool
}

// newFdTun takes a file descriptor that does not block
func newFdTun(fd, vnet int) *fdTun {
	t := &fdTun{fd: fd, file: os.NewFile(uintptr(fd), "/dev/net/tun"), vnet: vnet}
	t.raw, _ = t.file.SyscallConn()
	t.readv = func(fd uintptr) bool {
		for {
			n, _, errno := unix.Syscall(unix.SYS_READV, fd, uintptr(unsafe.Pointer(&t.iovecs[0])), uintptr(len(t.iovecs)))
			switch errno {
			case 0:
				t.read, t.readErr = int(n), nil
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return false
			default:
				t.read, t.readErr = 0, errno
			}
			return true
		}
	}
	return t
}

func (t *fdTun) ReadPacket(b []byte) ([]byte, error) {
	n, err := t.file.Read(b)
	// what the virtio_net_hdr says is of no use here: no checksum is looked at, and a segment may have any size
	return b[min(t.vnet, n):n], err
}

// ReadParts implements segmenter
func (t *fdTun) ReadParts(parts [][]byte) (int, error) {
	t.iovecs = append(t.iovecs[:0], unix.Iovec{Base: &t.header[0]})
	t.iovecs[0].SetLen(t.vnet)
	for i, p := range parts {
		t.iovecs = append(t.iovecs, unix.Iovec{Base: &p[0]})
		t.iovecs[i+1].SetLen(len(p))
	}
	if err := t.raw.Read(t.readv); err != nil {
		return 0, err
	}
	return max(t.read-t.vnet, 0), t.readErr
}

func (t *fdTun) WritePacket(header, payload []byte) error {
	// a virtio_net_hdr of zeros leaves nothing to the system
	var vnet [packetRoom]byte
	return t.writev(vnet[:t.vnet], header, payload)
}

// Segments implements segmenter
func (t *fdTun) Segments() bool {
	return t.vnet != 0
}

// WriteSegment implements segmenter
func (t *fdTun) WriteSegment(header []byte, payload [][]byte, mss int) error {
	// the virtio_net_hdr and the headers go as one part
	var b [packetRoom + ipv6HeaderSize + 60]byte
	ip, gso := ipv4HeaderSize, byte(unix.VIRTIO_NET_HDR_GSO_TCPV4)
	if header[0]>>4 == 6 {
		ip, gso = ipv6HeaderSize, unix.VIRTIO_NET_HDR_GSO_TCPV6
	}
	size := 0
	for _, p := range payload {
		size += len(p)
	}
	b[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	if size > mss {
		b[1] = gso
		binary.NativeEndian.PutUint16(b[4:], uint16(mss))
	}
	binary.NativeEndian.PutUint16(b[2:], uint16(len(header)))
	// where the checksum starts, and where it is put from there
	binary.NativeEndian.PutUint16(b[6:], uint16(ip))
	binary.NativeEndian.PutUint16(b[8:], 16)
	var parts [8][]byte
	return t.writev(append(append(parts[:0], b[:t.vnet+copy(b[t.vnet:], header)]), payload...)...)
}

func (t *fdTun) writev(parts ...[]byte) error {
	t.writeLock.RLock()
	defer t.writeLock.RUnlock()
	if t.closed {
		return os.ErrClosed
	}
	for {
		_, err := unix.Writev(t.fd, parts)
		if err != unix.EINTR {
			return err
		}
	}
}

func (t *fdTun) closeFile() error {
	t.writeLock.Lock()
	defer t.writeLock.Unlock()
	t.closed = true
	return t.file.Close()
}
