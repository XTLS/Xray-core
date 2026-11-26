//go:build linux && !android

package net

import (
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestFindProcessIPv4Mapped(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	// an IPv6 socket that connects to an IPv4 address, as the sockets of Java and .NET are
	for _, c := range []struct{ local, remote stdnet.Addr }{
		{&stdnet.TCPAddr{IP: stdnet.IPv6zero}, listener.Addr()},
		{&stdnet.UDPAddr{IP: stdnet.IPv6zero}, peer.LocalAddr()},
	} {
		network := c.remote.Network()
		conn, err := (&stdnet.Dialer{LocalAddr: c.local}).Dial(network, c.remote.String())
		if errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Skip("no IPv6 sockets here")
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		local := netip.MustParseAddrPort(conn.LocalAddr().String())
		remote := netip.MustParseAddrPort(c.remote.String())
		pid, _, _, err := FindProcess(network, "127.0.0.1", local.Port(), "127.0.0.1", remote.Port())
		if err != nil {
			t.Errorf("%s: %v", network, err)
		} else if pid != os.Getpid() {
			t.Errorf("%s: found PID %d, want %d", network, pid, os.Getpid())
		}
	}
}

func TestFindInodeInFilesSkipsSocketsWithoutProcess(t *testing.T) {
	// a socket in TIME_WAIT has no process and has inode 0, and a new socket can have the same local address
	file := filepath.Join(t.TempDir(), "tcp")
	err := os.WriteFile(file, []byte(strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:A1B2 0100007F:0050 06 00000000:00000000 03:00000F3C 00000000     0        0 0 3 0000000000000000",
		"   1: 0100007F:A1B2 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 4 30 10 -1",
	}, "\n")), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	inode, err := findInodeInFiles([]string{file}, []string{"0100007F:A1B2"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if inode != "123456" {
		t.Errorf("found inode %q, want 123456", inode)
	}
}

// TestHelperProcess is not a test: BenchmarkFindProcess runs it in other processes.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("XRAY_TEST_HELPER") != "1" {
		return
	}
	var command string
	fmt.Scanln(&command)
	switch command {
	case "fds":
		// many open files, as on a loaded system
		n := 0
		for n < 50000 {
			if _, err := syscall.Open(os.DevNull, syscall.O_RDONLY, 0); err != nil {
				break
			}
			n++
		}
		fmt.Println(n)
	case "udp":
		conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		fmt.Println(conn.LocalAddr().(*stdnet.UDPAddr).Port)
	}
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

type helperProcess struct {
	cmd    *exec.Cmd
	stdin  io.Writer
	stdout io.Reader
}

func startHelperProcess(b *testing.B) *helperProcess {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "XRAY_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})
	return &helperProcess{cmd: cmd, stdin: stdin, stdout: stdout}
}

func (h *helperProcess) run(b *testing.B, command string) int {
	if _, err := fmt.Fprintln(h.stdin, command); err != nil {
		b.Fatal(err)
	}
	var n int
	if _, err := fmt.Fscan(h.stdout, &n); err != nil {
		b.Fatal(err)
	}
	return n
}

// BenchmarkFindProcess finds the owner of a socket while another process holds many fds.
func BenchmarkFindProcess(b *testing.B) {
	// the lookup reads the processes in the order of os.ReadDir("/proc"), that is by the PID as a string:
	// the process with many fds must come first
	holder, owner := startHelperProcess(b), startHelperProcess(b)
	if strconv.Itoa(owner.cmd.Process.Pid) < strconv.Itoa(holder.cmd.Process.Pid) {
		holder, owner = owner, holder
	}
	b.Logf("other process holds %d fds", holder.run(b, "fds"))
	port := uint16(owner.run(b, "udp"))

	b.Run("FindProcess", func(b *testing.B) {
		for b.Loop() {
			if _, _, _, err := FindProcess("udp", "127.0.0.1", port, "", 0); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("FindProcessMatching", func(b *testing.B) {
		// as with self/: only the owner is accepted
		accept := func(pid int, _, _ string) bool { return pid == owner.cmd.Process.Pid }
		for b.Loop() {
			if _, _, _, err := FindProcessMatching("udp", "127.0.0.1", port, "", 0, accept); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("FindProcessMatchingNone", func(b *testing.B) {
		// no process is accepted: only the exe link of each process is read
		accept := func(int, string, string) bool { return false }
		for b.Loop() {
			if _, _, _, err := FindProcessMatching("udp", "127.0.0.1", port, "", 0, accept); err != ErrProcessNotMatched {
				b.Fatal(err)
			}
		}
	})
}
