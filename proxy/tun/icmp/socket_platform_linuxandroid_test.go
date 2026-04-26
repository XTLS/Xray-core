//go:build linux || android

package icmp

import (
	stderrors "errors"
	stdnet "net"
	"runtime"
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
	wantRawSkip := runtime.GOOS == "linux"
	if shouldSkip != wantRawSkip {
		t.Fatalf("unexpected raw socket skip decision: got %v want %v", shouldSkip, wantRawSkip)
	}
}

func TestShouldSkipSyntheticReplyForLinuxAndroid(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		network string
		want    bool
	}{
		{name: "linux datagram", goos: "linux", network: "udp4", want: true},
		{name: "linux raw", goos: "linux", network: "ip4:icmp", want: true},
		{name: "android datagram", goos: "android", network: "udp4", want: true},
		{name: "android raw", goos: "android", network: "ip4:icmp", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSkipSyntheticReplyForLinuxAndroid(tt.goos, tt.network); got != tt.want {
				t.Fatalf("shouldSkipSyntheticReplyForLinuxAndroid(%q, %q) = %v, want %v", tt.goos, tt.network, got, tt.want)
			}
		})
	}
}
