package proxy_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type visionRawConn struct {
	net.Conn
	written     bytes.Buffer
	suppressed  bool
	beforeWrite func()
	writeError  error
}

func (c *visionRawConn) Write(p []byte) (int, error) {
	if c.beforeWrite != nil {
		c.beforeWrite()
	}
	if c.writeError != nil {
		return 0, c.writeError
	}
	return c.written.Write(p)
}
func (c *visionRawConn) SuppressCloseNotify() { c.suppressed = true }

type visionWriteFunc func(buf.MultiBuffer) error

func (f visionWriteFunc) WriteMultiBuffer(mb buf.MultiBuffer) error { return f(mb) }

func visionTLSRecord(kind byte, size int) []byte {
	record := make([]byte, size+5)
	copy(record, []byte{kind, 3, 3, byte(size >> 8), byte(size)})
	for i := 5; i < len(record); i++ {
		record[i] = byte(i)
	}
	if size > 100 {
		// A header-looking sequence inside ciphertext is not a record boundary.
		copy(record[50:], []byte{23, 3, 3, 0, 1, 0})
	}
	return record
}

// Decode the padding independently of the writer and return the inner bytes.
func visionPaddedContent(t *testing.T, wire, uuid []byte, terminal byte) []byte {
	t.Helper()
	if !bytes.HasPrefix(wire, uuid) {
		t.Fatal("missing Vision UUID")
	}
	wire = wire[len(uuid):]
	var content []byte
	last := proxy.CommandPaddingContinue
	for len(wire) != 0 {
		if len(wire) < 5 {
			t.Fatal("truncated padding header")
		}
		if last != proxy.CommandPaddingContinue {
			t.Fatal("padding after terminal command")
		}
		last = wire[0]
		n := int(binary.BigEndian.Uint16(wire[1:3]))
		padding := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+n+padding {
			t.Fatal("truncated padding content")
		}
		content = append(content, wire[5:5+n]...)
		wire = wire[5+n+padding:]
	}
	if last != terminal {
		t.Fatalf("last padding command = %d, want %d", last, terminal)
	}
	return content
}

func TestVisionWriterTLSRecordBoundaries(t *testing.T) {
	application := visionTLSRecord(23, 16401) // Full-size TLS 1.3 ciphertext.
	handshake := append(visionTLSRecord(22, 96), visionTLSRecord(20, 1)...)
	for _, uplink := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			prefix    []byte
			firstRead int
		}{
			{"aligned", nil, len(application)},
			{"split-payload", nil, buf.Size},
			{"split-header-1", nil, 1},
			{"split-header", nil, 2},
			{"split-header-3", nil, 3},
			{"split-header-4", nil, 4},
			{"header-between-buffers", visionTLSRecord(22, buf.Size-7), 8 * buf.Size},
			{"coalesced-handshake", handshake, buf.Size},
		} {
			t.Run(fmt.Sprintf("uplink=%t/%s", uplink, tc.name), func(t *testing.T) {
				uuid := bytes.Repeat([]byte{0x42}, 16)
				state := proxy.NewTrafficState(uuid)
				state.NumberOfPacketToFilter = 0
				state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, true
				var outer bytes.Buffer
				raw := new(visionRawConn)
				writer := proxy.NewVisionWriter(buf.NewWriter(&outer), state, uplink, context.Background(), raw, nil, nil)
				stream := append(append(bytes.Clone(tc.prefix), application...), bytes.Repeat(application, 10)...)
				for offset, size := 0, tc.firstRead; offset < len(stream); size = 8 * buf.Size {
					end := min(offset+size, len(stream))
					if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, stream[offset:end])); err != nil {
						t.Fatal(err)
					}
					offset = end
				}
				boundary := len(tc.prefix) + len(application)
				padded := visionPaddedContent(t, outer.Bytes(), uuid, proxy.CommandPaddingDirect)
				if !bytes.Equal(padded, stream[:boundary]) {
					t.Fatalf("padded %d inner bytes, want first record boundary at %d", len(padded), boundary)
				}
				if !bytes.Equal(raw.written.Bytes(), stream[boundary:]) {
					t.Fatalf("raw copy got %d bytes, want %d", raw.written.Len(), len(stream)-boundary)
				}
				if !raw.suppressed {
					t.Fatal("outer close_notify not suppressed")
				}
			})
		}
	}
}

func TestVisionWriterIncompleteOrInvalidRecord(t *testing.T) {
	for name, input := range map[string][]byte{
		"incomplete-header": {23, 3, 3, 1},
		"incomplete-body":   visionTLSRecord(23, 100)[:99],
		"invalid-type":      {0, 3, 3, 0, 1, 0},
		"invalid-version":   {23, 3, 4, 0, 1, 0},
		"empty-record":      {23, 3, 3, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			uuid := bytes.Repeat([]byte{0x42}, 16)
			state := proxy.NewTrafficState(uuid)
			state.NumberOfPacketToFilter = 0
			state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, true
			var outer bytes.Buffer
			raw := new(visionRawConn)
			writer := proxy.NewVisionWriter(buf.NewWriter(&outer), state, true, context.Background(), raw, nil, nil)
			if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, input)); err != nil {
				t.Fatal(err)
			}
			if name == "invalid-type" || name == "invalid-version" || name == "empty-record" {
				// Do not resynchronize on header-looking bytes after malformed data.
				next := visionTLSRecord(23, 32)
				if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, next)); err != nil {
					t.Fatal(err)
				}
				input = append(bytes.Clone(input), next...)
			}
			if content := visionPaddedContent(t, outer.Bytes(), uuid, proxy.CommandPaddingContinue); !bytes.Equal(content, input) {
				t.Fatal("padded content changed")
			}
			if raw.written.Len() != 0 || raw.suppressed || !state.Outbound.IsPadding {
				t.Fatal("switched without a complete TLS record")
			}
		})
	}
}

func TestVisionWriterTracksBeforeTLS13(t *testing.T) {
	uuid := bytes.Repeat([]byte{0x42}, 16)
	state := proxy.NewTrafficState(uuid)
	state.NumberOfPacketToFilter = 0
	state.IsTLS, state.IsTLS12orAbove = true, true
	var outer bytes.Buffer
	raw := new(visionRawConn)
	writer := proxy.NewVisionWriter(buf.NewWriter(&outer), state, true, context.Background(), raw, nil, nil)
	hello := visionTLSRecord(22, 100)
	hello[2] = 1 // ClientHello's legacy record version can be TLS 1.0.
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, hello[:23])); err != nil {
		t.Fatal(err)
	}
	state.EnableXtls = true
	application := visionTLSRecord(23, 100)
	input := append(append(bytes.Clone(hello[23:]), application...), application...)
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, input)); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(hello), application...)
	if content := visionPaddedContent(t, outer.Bytes(), uuid, proxy.CommandPaddingDirect); !bytes.Equal(content, want) {
		t.Fatal("did not retain the handshake record boundary")
	}
	if !bytes.Equal(raw.written.Bytes(), application) {
		t.Fatal("raw content changed")
	}
}

func TestVisionWriterTLS12(t *testing.T) {
	uuid := bytes.Repeat([]byte{0x42}, 16)
	state := proxy.NewTrafficState(uuid)
	state.NumberOfPacketToFilter = 0
	state.IsTLS, state.IsTLS12orAbove = true, true
	var outer bytes.Buffer
	raw := new(visionRawConn)
	writer := proxy.NewVisionWriter(buf.NewWriter(&outer), state, true, context.Background(), raw, nil, nil)
	input := visionTLSRecord(23, 100)
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, input)); err != nil {
		t.Fatal(err)
	}
	if content := visionPaddedContent(t, outer.Bytes(), uuid, proxy.CommandPaddingEnd); !bytes.Equal(content, input) {
		t.Fatal("TLS 1.2 content changed")
	}
	outerSize := outer.Len()
	if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, input)); err != nil {
		t.Fatal(err)
	}
	if raw.written.Len() != 0 || raw.suppressed || !bytes.Equal(outer.Bytes()[outerSize:], input) {
		t.Fatal("TLS 1.2 must stay on the outer connection without padding")
	}
}

func TestVisionWriterSwitchOrdering(t *testing.T) {
	failure := errors.New("write failed")
	for _, phase := range []string{"success", "padding-failure", "raw-failure"} {
		t.Run(phase, func(t *testing.T) {
			uuid := bytes.Repeat([]byte{0x42}, 16)
			state := proxy.NewTrafficState(uuid)
			state.NumberOfPacketToFilter = 0
			state.IsTLS, state.IsTLS12orAbove, state.EnableXtls = true, true, true
			inbound := &session.Inbound{CanSpliceCopy: 2}
			ctx := session.ContextWithInbound(context.Background(), inbound)
			var outer bytes.Buffer
			raw := new(visionRawConn)
			if phase == "raw-failure" {
				raw.writeError = failure
			}
			raw.beforeWrite = func() {
				if !raw.suppressed || inbound.CanSpliceCopy != 2 {
					t.Fatal("close_notify suppression or splice ordering violated")
				}
				visionPaddedContent(t, outer.Bytes(), uuid, proxy.CommandPaddingDirect)
			}
			outerWriter := visionWriteFunc(func(mb buf.MultiBuffer) error {
				if raw.suppressed {
					t.Fatal("suppressed outer TLS before writing terminal padding")
				}
				if phase == "padding-failure" {
					buf.ReleaseMulti(mb)
					return failure
				}
				return buf.NewWriter(&outer).WriteMultiBuffer(mb)
			})
			counter := new(stats.Counter)
			conn := &stat.CounterConnection{Connection: raw, WriteCounter: counter}
			writer := proxy.NewVisionWriter(outerWriter, state, false, ctx, conn, nil, nil)
			record := visionTLSRecord(23, 100)
			err := writer.WriteMultiBuffer(buf.MergeBytes(nil, bytes.Repeat(record, 2)))
			if phase == "success" {
				if err != nil || inbound.CanSpliceCopy != 1 || counter.Value() != int64(len(record)) || !bytes.Equal(raw.written.Bytes(), record) {
					t.Fatalf("raw copy failed: err=%v, splice=%d, counter=%d", err, inbound.CanSpliceCopy, counter.Value())
				}
			} else if !errors.Is(err, failure) || inbound.CanSpliceCopy != 2 || raw.written.Len() != 0 {
				t.Fatalf("continued after failed write: err=%v, splice=%d", err, inbound.CanSpliceCopy)
			}
			if phase == "padding-failure" && raw.suppressed {
				t.Fatal("switched after failed padding write")
			}
		})
	}
}
