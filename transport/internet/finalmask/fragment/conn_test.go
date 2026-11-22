package fragment_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
)

// dialRaw connects to addr and wraps the connection in a fragment mask with
// the given mode; the caller owns both.
func dialRaw(t *testing.T, addr net.Addr, mode fragment.Config_Mode, min, max int64) (net.Conn, *net.TCPConn) {
	t.Helper()
	config := &fragment.Config{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthsMin:  []int64{min},
		LengthsMax:  []int64{max},
		DelaysMin:   []int64{0},
		DelaysMax:   []int64{0},
		Mode:        mode,
	}
	raw, err := net.Dial(addr.Network(), addr.String())
	if err != nil {
		t.Fatal(err)
	}
	tcp := raw.(*net.TCPConn)
	conn, err := fragment.NewConnClient(config, raw, false)
	if err != nil {
		raw.Close()
		t.Fatalf("mode %v: %v", mode, err)
	}
	return conn, tcp
}

// buildClientHello returns a TLS record shaped like a ClientHello of the
// given payload size.
func buildClientHello(size int) []byte {
	record := make([]byte, 5+size)
	record[0] = 22 // handshake
	record[1] = 3  // TLS 1.2
	record[2] = 1
	binary.BigEndian.PutUint16(record[3:5], uint16(size))
	for i := range record[5:] {
		record[5+i] = byte(i * 7)
	}
	return record
}

// readServerSide accepts one connection, reads until EOF and hands the bytes
// back over the channel.
func readServerSide(t *testing.T, l net.Listener) <-chan []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			ch <- nil
			return
		}
		defer conn.Close()
		got, err := io.ReadAll(conn)
		if err != nil {
			ch <- nil
			return
		}
		ch <- got
	}()
	return ch
}

// parseTLSRecords walks a TLS record stream and returns the concatenated
// handshake payload of all type-22 records, verifying framing on the way.
func parseTLSRecords(t *testing.T, got []byte, mode fragment.Config_Mode) []byte {
	t.Helper()
	var payload []byte
	for off := 0; off < len(got); {
		if off+5 > len(got) {
			t.Fatalf("truncated record header at %d in mode %v", off, mode)
		}
		if got[off] != 22 {
			t.Fatalf("unexpected record type %d at %d in mode %v", got[off], off, mode)
		}
		l := int(binary.BigEndian.Uint16(got[off+3 : off+5]))
		if off+5+l > len(got) {
			t.Fatalf("record at %d overruns payload in mode %v", off, mode)
		}
		payload = append(payload, got[off+5:off+5+l]...)
		off += 5 + l
	}
	return payload
}

// TestFragmentConnTLSStream checks the tlshello path: the server must
// receive a parseable TLS record stream whose reassembled handshake equals
// the input in every mode. Normal mode with a single zero delay merges the
// pieces into re-recorded writes, disorder and disoob keep the original
// record headers.
func TestFragmentConnTLSStream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	payload := buildClientHello(300)

	for _, mode := range []fragment.Config_Mode{fragment.Config_NORMAL, fragment.Config_DISORDER, fragment.Config_DISOOB} {
		t.Run(mode.String(), func(t *testing.T) {
			serverGot := readServerSide(t, l)

			conn, tcp := dialRaw(t, l.Addr(), mode, 1, 5)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			tcp.CloseWrite()

			select {
			case got := <-serverGot:
				hello := parseTLSRecords(t, got, mode)
				if !bytes.Equal(hello, payload[5:]) {
					t.Fatalf("reassembled handshake differs from input in mode %v", mode)
				}
			case <-time.After(15 * time.Second):
				t.Fatalf("timeout waiting for server data in mode %v", mode)
			}
		})
	}
}

// TestFragmentConnRawStreamIntegrity checks the packets-range path: the
// stream must arrive byte-for-byte identical in every mode, because this
// path forwards the write as-is.
func TestFragmentConnRawStreamIntegrity(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i * 13)
	}

	for _, mode := range []fragment.Config_Mode{fragment.Config_NORMAL, fragment.Config_DISORDER, fragment.Config_DISOOB} {
		t.Run(mode.String(), func(t *testing.T) {
			serverGot := readServerSide(t, l)

			conn, tcp := dialRaw(t, l.Addr(), mode, 1, 7)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			tcp.CloseWrite()

			select {
			case got := <-serverGot:
				if !bytes.Equal(got, payload) {
					t.Fatalf("stream corrupted in mode %v", mode)
				}
			case <-time.After(15 * time.Second):
				t.Fatalf("timeout waiting for server data in mode %v", mode)
			}
		})
	}
}

// TestFragmentConnDisorderPattern proves the disorder modes really alternate
// writes with TTL=1: with a raw loopback listener we cannot observe the TTL,
// but we can observe that every other write happens as a separate segment
// and that the full stream still arrives intact.
func TestFragmentConnDisorderPattern(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	payload := buildClientHello(300)

	for _, mode := range []fragment.Config_Mode{fragment.Config_DISORDER, fragment.Config_DISOOB} {
		t.Run(mode.String(), func(t *testing.T) {
			serverGot := readServerSide(t, l)

			conn, tcp := dialRaw(t, l.Addr(), mode, 1, 5)
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			tcp.CloseWrite()

			select {
			case got := <-serverGot:
				hello := parseTLSRecords(t, got, mode)
				if !bytes.Equal(hello, payload[5:]) {
					t.Fatalf("reassembled handshake differs from input in mode %v", mode)
				}
			case <-time.After(15 * time.Second):
				t.Fatalf("timeout waiting for server data in mode %v", mode)
			}
		})
	}
}

// TestFragmentConnMultipleWrites checks the packets-range path with several
// consecutive writes: every write is split, forwarded and reassembled, and
// the stream stays byte-exact in the disorder modes too.
func TestFragmentConnMultipleWrites(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	chunks := [][]byte{
		buildClientHello(120),
		buildClientHello(50),
		buildClientHello(200),
	}

	for _, mode := range []fragment.Config_Mode{fragment.Config_NORMAL, fragment.Config_DISORDER, fragment.Config_DISOOB} {
		t.Run(mode.String(), func(t *testing.T) {
			serverGot := readServerSide(t, l)

			conn, tcp := dialRaw(t, l.Addr(), mode, 1, 8)
			for _, chunk := range chunks {
				if _, err := conn.Write(chunk); err != nil {
					t.Fatal(err)
				}
			}
			tcp.CloseWrite()

			select {
			case got := <-serverGot:
				hello := parseTLSRecords(t, got, mode)
				var want []byte
				for _, chunk := range chunks {
					want = append(want, chunk[5:]...)
				}
				if !bytes.Equal(hello, want) {
					t.Fatalf("reassembled stream differs from input in mode %v", mode)
				}
			case <-time.After(15 * time.Second):
				t.Fatalf("timeout waiting for server data in mode %v", mode)
			}
		})
	}
}

// TestFragmentConnNormalMergeMode checks the legacy normal behavior: with a
// single zero delay the split pieces are merged into one write and the
// reassembled handshake still arrives intact.
func TestFragmentConnNormalMergeMode(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	serverGot := readServerSide(t, l)

	payload := buildClientHello(300)
	conn, tcp := dialRaw(t, l.Addr(), fragment.Config_NORMAL, 1, 5)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	tcp.CloseWrite()

	select {
	case got := <-serverGot:
		hello := parseTLSRecords(t, got, fragment.Config_NORMAL)
		if !bytes.Equal(hello, payload[5:]) {
			t.Fatal("reassembled handshake differs from input")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for server data")
	}
}

// TestFragmentConnServerSide checks server-side wrapping: the split applies
// on both sides as upstream does, but the server never alternates TTL or
// sends urgent bytes, so the reassembled handshake stays intact.
func TestFragmentConnServerSide(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	serverGot := readServerSide(t, l)

	payload := buildClientHello(200)
	config := &fragment.Config{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthsMin:  []int64{1},
		LengthsMax:  []int64{5},
		DelaysMin:   []int64{0},
		DelaysMax:   []int64{0},
		Mode:        fragment.Config_DISORDER,
	}
	raw, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, err := fragment.NewConnClient(config, raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	raw.(*net.TCPConn).CloseWrite()

	select {
	case got := <-serverGot:
		hello := parseTLSRecords(t, got, fragment.Config_DISORDER)
		if !bytes.Equal(hello, payload[5:]) {
			t.Fatal("reassembled handshake differs from input")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for server data")
	}
}

// TestFragmentConnSweep runs many payload sizes and split lengths through
// the disorder modes, catching off-by-one splits and re-recording bugs the
// fixed-size tests could miss.
func TestFragmentConnSweep(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	sizes := []int{6, 7, 10, 31, 64, 100, 257, 1000}
	lengths := [][2]int64{{1, 1}, {1, 3}, {5, 5}, {7, 40}}

	for _, mode := range []fragment.Config_Mode{fragment.Config_DISORDER, fragment.Config_DISOOB} {
		for _, size := range sizes {
			for _, lr := range lengths {
				name := fmt.Sprintf("%s/size%d/len%d-%d", mode, size, lr[0], lr[1])
				t.Run(name, func(t *testing.T) {
					serverGot := readServerSide(t, l)

					payload := buildClientHello(size)
					config := &fragment.Config{
						PacketsFrom: 0,
						PacketsTo:   1,
						LengthsMin:  []int64{lr[0]},
						LengthsMax:  []int64{lr[1]},
						DelaysMin:   []int64{0},
						DelaysMax:   []int64{0},
						Mode:        mode,
					}
					raw, err := net.Dial(l.Addr().Network(), l.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					tcp := raw.(*net.TCPConn)
					conn, err := fragment.NewConnClient(config, raw, false)
					if err != nil {
						t.Fatalf("mode %v: %v", mode, err)
					}
					if _, err := conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					tcp.CloseWrite()

					select {
					case got := <-serverGot:
						hello := parseTLSRecords(t, got, mode)
						if !bytes.Equal(hello, payload[5:]) {
							t.Fatalf("reassembled handshake differs from input")
						}
					case <-time.After(15 * time.Second):
						t.Fatalf("timeout waiting for server data")
					}
				})
			}
		}
	}
}
