//go:build (linux && !android) || windows || (darwin && !ios)

package net

import (
	stdnet "net"
	"os"
	"testing"
)

func TestFindProcessMatching(t *testing.T) {
	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*stdnet.UDPAddr).Port)

	pid, name, absPath, err := FindProcess("udp", "127.0.0.1", port, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Fatalf("FindProcess found PID %d, want %d", pid, os.Getpid())
	}

	accepted := false
	gotPID, gotName, gotPath, err := FindProcessMatching("udp", "127.0.0.1", port, "", 0, func(p int, n, a string) bool {
		if p != pid {
			return false
		}
		if n != name || a != absPath {
			t.Errorf("accept got %q %q for PID %d, want %q %q", n, a, p, name, absPath)
		}
		accepted = true
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if !accepted {
		t.Error("accept was not called for the owner of the socket")
	}
	if gotPID != pid || gotName != name || gotPath != absPath {
		t.Errorf("FindProcessMatching found %d %q %q, want %d %q %q", gotPID, gotName, gotPath, pid, name, absPath)
	}

	_, _, _, err = FindProcessMatching("udp", "127.0.0.1", port, "", 0, func(int, string, string) bool { return false })
	if err != ErrProcessNotMatched {
		t.Errorf("FindProcessMatching that accepts nothing returned %v, want ErrProcessNotMatched", err)
	}

	gotPID, _, _, err = FindProcessMatching("udp", "127.0.0.1", port, "", 0, nil)
	if err != nil || gotPID != pid {
		t.Errorf("FindProcessMatching without accept found %d, %v, want %d", gotPID, err, pid)
	}
}
