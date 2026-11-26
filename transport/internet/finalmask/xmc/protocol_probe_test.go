package xmc

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// statusTestServer answers exactly one status exchange with the given version.
func statusTestServer(t *testing.T, listener net.Listener, protocol int32, name string) {
	t.Helper()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := readPacket(conn); err != nil {
			return
		}
		if _, err := readPacket(conn); err != nil {
			return
		}
		payload := String(fmt.Sprintf(`{"description":"test","players":{"max":0,"online":0},"version":{"name":%q,"protocol":%d}}`, name, protocol))
		_ = writePacket(conn, statusClientboundResponse, &payload)
	}()
}

func statusTestDestination(t *testing.T, listener net.Listener) xnet.Destination {
	t.Helper()
	dest, err := xnet.ParseDestination("tcp:" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return dest
}

func statusTestDialer(dialErr error) *finalmask.Dialer {
	return &finalmask.Dialer{DialTCP: func(dest xnet.Destination) (net.Conn, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return net.Dial("tcp", net.JoinHostPort(dest.Address.String(), strconv.Itoa(int(dest.Port.Value()))))
	}}
}

// TestProbeProtocolVersion reads the version out of the status response, which
// is the version the peer's login expects.
func TestProbeProtocolVersion(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	statusTestServer(t, listener, 767, "1.21.1")

	dest := statusTestDestination(t, listener)
	number, name, err := probeProtocolVersion(&dest, "localhost", statusTestDialer(nil))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if number != 767 || name != "1.21.1" {
		t.Fatalf("probe = %d %q, want 767 \"1.21.1\"", number, name)
	}
}

func TestProbeProtocolVersionRejectsBrokenPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = readPacket(conn)
		_, _ = readPacket(conn)
		payload := String(`{"description":"no version here"}`)
		_ = writePacket(conn, statusClientboundResponse, &payload)
	}()

	dest := statusTestDestination(t, listener)
	if _, _, err := probeProtocolVersion(&dest, "localhost", statusTestDialer(nil)); err == nil || !strings.Contains(err.Error(), "no version") {
		t.Fatalf("probe error = %v", err)
	}

	if _, _, err := probeProtocolVersion(&dest, "localhost", nil); err == nil || !strings.Contains(err.Error(), "no TCP dialer") {
		t.Fatalf("nil dialer error = %v", err)
	}
	if _, _, err := probeProtocolVersion(nil, "localhost", statusTestDialer(nil)); err == nil || !strings.Contains(err.Error(), "no destination") {
		t.Fatalf("nil destination error = %v", err)
	}
}

// TestDetectProtocolVersionCaches checks a destination is probed once per TTL:
// the second call must answer from the cache even though dialing now fails.
func TestDetectProtocolVersionCaches(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	statusTestServer(t, listener, 776, "26.2")
	dest := statusTestDestination(t, listener)

	number, name, err := detectProtocolVersion(&dest, "localhost", statusTestDialer(nil))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if number != 776 || name != "26.2" {
		t.Fatalf("detect = %d %q", number, name)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	number, _, err = detectProtocolVersion(&dest, "localhost", statusTestDialer(fmt.Errorf("must not dial")))
	if err != nil {
		t.Fatalf("cached detect: %v", err)
	}
	if number != 776 {
		t.Fatalf("cached detect = %d", number)
	}
}

// TestClientProtocol covers the three ways the client picks its row: a
// configured version, a detected one, and the fallback when the peer does not
// answer status.
func TestClientProtocol(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		// No destination and no dialer: a configured version must not probe.
		version, err := (&Config{ProtocolVersion: 775}).clientProtocol(nil, nil)
		if err != nil || version.number != 775 {
			t.Fatalf("configured = %v, %v", version.number, err)
		}
	})

	t.Run("detected", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		statusTestServer(t, listener, 767, "1.21.1")
		dest := statusTestDestination(t, listener)

		version, err := (&Config{}).clientProtocol(&dest, statusTestDialer(nil))
		if err != nil || version.number != 767 || version.name != "1.21.1" {
			t.Fatalf("detected = %v %q, %v", version.number, version.name, err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		statusTestServer(t, listener, 999, "999")
		dest := statusTestDestination(t, listener)

		if _, err := (&Config{}).clientProtocol(&dest, statusTestDialer(nil)); err == nil || !strings.Contains(err.Error(), "not in the supported table") {
			t.Fatalf("unknown version error = %v", err)
		}
	})

	t.Run("probe failure falls back to the newest row", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		dest, err := xnet.ParseDestination("tcp:" + address)
		if err != nil {
			t.Fatal(err)
		}

		version, err := (&Config{}).clientProtocol(&dest, statusTestDialer(nil))
		if err != nil {
			t.Fatalf("fallback: %v", err)
		}
		if version.number != latestProtocolVersion.number {
			t.Fatalf("fallback version = %d, want %d", version.number, latestProtocolVersion.number)
		}
	})
}
