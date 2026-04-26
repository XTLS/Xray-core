//go:build linux || android

package icmp

import (
	stderrors "errors"
	stdnet "net"
	"testing"
)

func TestIsPermissionError(t *testing.T) {
	if !isPermissionError(stderrors.New("socket: permission denied")) {
		t.Fatal("expected permission denied to be recognized")
	}
	if !isPermissionError(stderrors.New("listen ip4:icmp 0.0.0.0: socket: operation not permitted")) {
		t.Fatal("expected operation not permitted to be recognized")
	}
	if isPermissionError(stderrors.New("i/o timeout")) {
		t.Fatal("did not expect timeout to be recognized as permission issue")
	}
}

func TestShouldSkipSyntheticReply(t *testing.T) {
	originalChecker := localIPChecker
	t.Cleanup(func() {
		localIPChecker = originalChecker
	})

	localIPChecker = func(ip stdnet.IP) (bool, error) {
		return ip.Equal(stdnet.IPv4(198, 18, 0, 1)), nil
	}

	socket := &Socket{Network: "udp4"}
	shouldSkip, err := socket.ShouldSkipSyntheticReply(stdnet.IPv4(198, 18, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !shouldSkip {
		t.Fatal("expected local datagram reply to skip synthetic injection")
	}

	shouldSkip, err = socket.ShouldSkipSyntheticReply(stdnet.IPv4(198, 18, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	if shouldSkip {
		t.Fatal("expected non-local source to keep synthetic injection")
	}

	rawSocket := &Socket{Network: "ip4:icmp"}
	shouldSkip, err = rawSocket.ShouldSkipSyntheticReply(stdnet.IPv4(198, 18, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if shouldSkip {
		t.Fatal("expected raw socket path to keep synthetic injection")
	}
}
