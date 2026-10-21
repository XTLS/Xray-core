//go:build linux

package tun

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A tun with a virtio_net_hdr reads one packet at a time into parts, without the header, waits for the next one,
// and stops waiting when it is closed.
func TestReadParts(t *testing.T) {
	// what a tun is like: one packet for every read, and a file descriptor that does not block
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	tun := newFdTun(fds[0], vnetSize)
	defer tun.closeFile()

	large := make([]byte, 20000)
	rand.Read(large)
	parts := [][]byte{make([]byte, 8192), make([]byte, 8192), make([]byte, 8192)}
	send := func(packet []byte) {
		if _, err := unix.Write(fds[1], append(bytes.Repeat([]byte{0xee}, vnetSize), packet...)); err != nil {
			t.Error(err)
		}
	}
	send(large)
	send([]byte("small"))
	for _, packet := range [][]byte{large, []byte("small")} {
		n, err := tun.ReadParts(parts)
		if err != nil || n != len(packet) || !bytes.Equal(bytes.Join(parts, nil)[:n], packet) {
			t.Fatal("read ", n, " bytes of ", len(packet), ", error: ", err)
		}
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		send([]byte("later"))
	}()
	if n, err := tun.ReadParts(parts); err != nil || string(parts[0][:n]) != "later" {
		t.Fatal("read ", parts[0][:n], " after waiting, error: ", err)
	}

	read := make(chan error)
	go func() {
		_, err := tun.ReadParts(parts)
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	tun.closeFile()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read after the tun was closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waits after the tun was closed")
	}
}
