package splithttp_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// listenFlush starts a real XHTTP listener whose handler stays silent for
// silentSecs after each echo -- long enough, without the patch, to sit past
// a small buffering intermediary's threshold -- then echoes back what it
// read. This is a stand-in for "a CDN holding the tail of our response";
// the test doesn't simulate a CDN, it verifies the patch's own plumbing
// (negotiation, framing, padding, unframing) is correct end-to-end and that
// real payload integrity survives padding flushes happening in between.
func listenFlush(t *testing.T, cfg *Config) (net.Port, func()) {
	port := tcp.PickPort()
	ln, err := ListenXH(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: cfg,
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}(conn)
	})
	common.Must(err)
	return port, func() { ln.Close() }
}

func TestDownlinkFlushEndToEnd(t *testing.T) {
	serverCfg := &Config{
		Path: "/fl",
		// the server's entire opt-in to downlink keepalive/framing is this
		// header name being non-empty -- see hub.go. An unconfigured server
		// (empty ScDownlinkKeepAliveHeader) ignores the client's request entirely,
		// same as an unpatched server would.
		ScDownlinkKeepAliveHeader: "Downlink-Ka",
		ScDownlinkFlushBytes:      &RangeConfig{From: 4096, To: 4096},
		ScDownlinkFlushDelayMs:    &RangeConfig{From: 30, To: 30},
	}
	port, stop := listenFlush(t, serverCfg)
	defer stop()

	clientCfg := &Config{
		Path: "fl", Mode: "packet-up",
		ScDownlinkKeepAliveHeader: "Downlink-Ka", // must match the server's
		ScDownlinkKeepAliveSecs:   &RangeConfig{From: 1, To: 1},
	}
	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), port),
		&internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: clientCfg})
	common.Must(err)
	defer conn.Close()

	for i, msg := range []string{"first", "a bit longer message here", "third"} {
		common.Must2(conn.Write([]byte(msg)))
		// give the pacer time to fire at least one idle-triggered padding
		// flush before we read -- if padding ever leaked through, this
		// would corrupt the echoed bytes
		time.Sleep(80 * time.Millisecond)
		got := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("msg %d: got %q, want %q (padding leaked into stream?)", i, got, msg)
		}
	}
}

func TestDownlinkFlushStockClientUnaffected(t *testing.T) {
	// A server with flush enabled (and opted in via ScDownlinkKeepAliveHeader) must
	// not send any framing at all to a client that never asked for it --
	// framing is negotiated, opt-in on both sides.
	serverCfg := &Config{
		Path:                      "/fl2",
		ScDownlinkKeepAliveHeader: "Downlink-Ka",
		ScDownlinkFlushBytes:      &RangeConfig{From: 4096, To: 4096},
		ScDownlinkFlushDelayMs:    &RangeConfig{From: 30, To: 30},
	}
	port, stop := listenFlush(t, serverCfg)
	defer stop()

	clientCfg := &Config{Path: "fl2", Mode: "packet-up"} // no ScDownlinkKeepAliveHeader -> no negotiation
	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), port),
		&internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: clientCfg})
	common.Must(err)
	defer conn.Close()

	msg := []byte("plain, unframed round trip")
	common.Must2(conn.Write(msg))
	time.Sleep(150 * time.Millisecond) // long enough that a (wrongly) active pacer would have fired
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestDownlinkFlushServerNotOptedIn checks backward compatibility the other
// way around: a client that asks for keepalive/framing (with a matching
// header name configured, so it genuinely tries) against a server that
// hasn't set scDownlinkKeepAliveHeader (an existing deployment that upgraded the
// binary but never touched its config) must fall back to a plain, unframed
// round trip -- the server does not silently start honoring a request it
// was never configured to accept.
func TestDownlinkFlushServerNotOptedIn(t *testing.T) {
	serverCfg := &Config{
		Path:                   "/fl3",
		ScDownlinkFlushBytes:   &RangeConfig{From: 4096, To: 4096},
		ScDownlinkFlushDelayMs: &RangeConfig{From: 30, To: 30},
		// deliberately no ScDownlinkKeepAliveHeader
	}
	port, stop := listenFlush(t, serverCfg)
	defer stop()

	clientCfg := &Config{
		Path: "fl3", Mode: "packet-up",
		ScDownlinkKeepAliveHeader: "Downlink-Ka",
		ScDownlinkKeepAliveSecs:   &RangeConfig{From: 1, To: 1},
	}
	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), port),
		&internet.MemoryStreamConfig{ProtocolName: "splithttp", ProtocolSettings: clientCfg})
	common.Must(err)
	defer conn.Close()

	msg := []byte("plain, unframed round trip")
	common.Must2(conn.Write(msg))
	time.Sleep(150 * time.Millisecond) // long enough that a (wrongly) active pacer would have fired
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q (server must not honor keepalive it never opted into)", got, msg)
	}
}
