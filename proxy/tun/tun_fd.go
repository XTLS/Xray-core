//go:build linux

package tun

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// fdTun reads and writes the packets of a tun that is a file descriptor
type fdTun struct {
	fd int
	// file is what packets are read from: a read waits in the poller of the runtime and ends when file is closed
	file *os.File

	writeLock sync.RWMutex
	closed    bool
}

// newFdTun takes a file descriptor that does not block
func newFdTun(fd int) *fdTun {
	return &fdTun{fd: fd, file: os.NewFile(uintptr(fd), "/dev/net/tun")}
}

func (t *fdTun) ReadPacket(b []byte) ([]byte, error) {
	n, err := t.file.Read(b)
	return b[:n], err
}

func (t *fdTun) WritePacket(header, payload []byte) error {
	t.writeLock.RLock()
	defer t.writeLock.RUnlock()
	if t.closed {
		return os.ErrClosed
	}
	for {
		_, err := unix.Writev(t.fd, [][]byte{header, payload})
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
