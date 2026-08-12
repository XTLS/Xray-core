//go:build openbsd
// +build openbsd

package udp

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRetrieveOriginalDestFromControlMessages(t *testing.T) {
	msgs := []unix.SocketControlMessage{
		{
			Header: unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_RECVDSTPORT},
			Data:   []byte{0x30, 0x39},
		},
		{
			Header: unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_RECVDSTADDR},
			Data:   []byte{203, 0, 113, 7},
		},
	}

	dest := retrieveOriginalDestFromControlMessages(msgs)
	if !dest.IsValid() {
		t.Fatal("destination is invalid")
	}
	if got, want := dest.Address.String(), "203.0.113.7"; got != want {
		t.Fatalf("address = %q, want %q", got, want)
	}
	if got, want := dest.Port.Value(), uint16(12345); got != want {
		t.Fatalf("port = %d, want %d", got, want)
	}
}

func TestRetrieveOriginalDestRequiresAddressAndPort(t *testing.T) {
	tests := [][]unix.SocketControlMessage{
		{
			{
				Header: unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_RECVDSTADDR},
				Data:   []byte{203, 0, 113, 7},
			},
		},
		{
			{
				Header: unix.Cmsghdr{Level: unix.IPPROTO_IP, Type: unix.IP_RECVDSTPORT},
				Data:   []byte{0x30, 0x39},
			},
		},
	}

	for _, msgs := range tests {
		if dest := retrieveOriginalDestFromControlMessages(msgs); dest.IsValid() {
			t.Fatalf("unexpected destination: %v", dest)
		}
	}
}
