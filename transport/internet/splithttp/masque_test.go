package splithttp

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/session"
)

type fakeMASQUEStream struct {
	ctx            context.Context
	streamReadBuf  bytes.Buffer
	streamWriteBuf bytes.Buffer
	datagramReads  [][]byte
	datagramWrites [][]byte
}

func (f *fakeMASQUEStream) Read(p []byte) (int, error) {
	return f.streamReadBuf.Read(p)
}

func (f *fakeMASQUEStream) Write(p []byte) (int, error) {
	return f.streamWriteBuf.Write(p)
}

func (f *fakeMASQUEStream) Close() error {
	return nil
}

func (f *fakeMASQUEStream) SendDatagram(p []byte) error {
	f.datagramWrites = append(f.datagramWrites, append([]byte(nil), p...))
	return nil
}

func (f *fakeMASQUEStream) ReceiveDatagram(context.Context) ([]byte, error) {
	if len(f.datagramReads) == 0 {
		return nil, io.EOF
	}
	data := f.datagramReads[0]
	f.datagramReads = f.datagramReads[1:]
	return append([]byte(nil), data...), nil
}

func (f *fakeMASQUEStream) Context() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return context.Background()
}

func (f *fakeMASQUEStream) SetDeadline(time.Time) error {
	return nil
}

func (f *fakeMASQUEStream) SetReadDeadline(time.Time) error {
	return nil
}

func (f *fakeMASQUEStream) SetWriteDeadline(time.Time) error {
	return nil
}

func masqueTelemetryDelta(before map[string]int64) map[string]int64 {
	after := globalMASQUETelemetry.globalSnapshot()
	delta := make(map[string]int64, len(after))
	for key, value := range after {
		delta[key] = value - before[key]
	}
	return delta
}

func masqueOutboundTelemetryDelta(outboundKey string, before map[string]int64) map[string]int64 {
	after := globalMASQUETelemetry.outboundSnapshotFor(outboundKey)
	delta := make(map[string]int64, len(after))
	for key, value := range after {
		delta[key] = value - before[key]
	}
	return delta
}

func TestMASQUEConnTelemetryTracksUsageAndFallback(t *testing.T) {
	before := globalMASQUETelemetry.globalSnapshot()

	stream := &fakeMASQUEStream{
		ctx: context.Background(),
		datagramReads: [][]byte{
			[]byte("pong"),
			[]byte("pong-2"),
		},
	}
	conn := newMASQUEConn(stream, nil, nil, nil, true, globalMASQUETelemetry.scope(masqueTelemetryUnscopedKey))

	if _, err := conn.Write([]byte("hdr")); err != nil {
		t.Fatal(err)
	}
	if got := stream.streamWriteBuf.String(); got != "hdr" {
		t.Fatalf("unexpected stream control write: %q", got)
	}

	if err := conn.EnableTransportDatagramWrite(); err != nil {
		t.Fatal(err)
	}
	if err := conn.EnableTransportDatagramRead(); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if len(stream.datagramWrites) != 1 || string(stream.datagramWrites[0]) != "ping" {
		t.Fatalf("unexpected datagram writes: %#v", stream.datagramWrites)
	}

	reply1 := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, reply1); err != nil {
		t.Fatal(err)
	}
	if string(reply1) != "pong" {
		t.Fatalf("unexpected reply1: %q", string(reply1))
	}

	reply2 := make([]byte, len("pong-2"))
	if _, err := io.ReadFull(conn, reply2); err != nil {
		t.Fatal(err)
	}
	if string(reply2) != "pong-2" {
		t.Fatalf("unexpected reply2: %q", string(reply2))
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	delta := masqueTelemetryDelta(before)
	if delta["requested_sessions"] != 1 {
		t.Fatalf("requested_sessions delta = %d", delta["requested_sessions"])
	}
	if delta["datagram_read_enabled_sessions"] != 1 {
		t.Fatalf("datagram_read_enabled_sessions delta = %d", delta["datagram_read_enabled_sessions"])
	}
	if delta["datagram_write_enabled_sessions"] != 1 {
		t.Fatalf("datagram_write_enabled_sessions delta = %d", delta["datagram_write_enabled_sessions"])
	}
	if delta["bidirectional_datagram_sessions"] != 1 {
		t.Fatalf("bidirectional_datagram_sessions delta = %d", delta["bidirectional_datagram_sessions"])
	}
	if delta["read_fallback_sessions"] != 0 || delta["write_fallback_sessions"] != 0 {
		t.Fatalf("unexpected fallback deltas: read=%d write=%d", delta["read_fallback_sessions"], delta["write_fallback_sessions"])
	}
	if delta["stream_write_ops"] != 1 || delta["stream_write_bytes"] != int64(len("hdr")) {
		t.Fatalf("unexpected stream write telemetry: ops=%d bytes=%d", delta["stream_write_ops"], delta["stream_write_bytes"])
	}
	if delta["datagram_write_packets"] != 1 || delta["datagram_write_bytes"] != int64(len("ping")) {
		t.Fatalf("unexpected datagram write telemetry: packets=%d bytes=%d", delta["datagram_write_packets"], delta["datagram_write_bytes"])
	}
	if delta["datagram_read_packets"] != 2 || delta["datagram_read_bytes"] != int64(len("pong")+len("pong-2")) {
		t.Fatalf("unexpected datagram read telemetry: packets=%d bytes=%d", delta["datagram_read_packets"], delta["datagram_read_bytes"])
	}
}

func TestMASQUEConnTelemetryTracksDirectionalFallback(t *testing.T) {
	before := globalMASQUETelemetry.globalSnapshot()

	stream := &fakeMASQUEStream{ctx: context.Background()}
	conn := newMASQUEConn(stream, nil, nil, nil, true, globalMASQUETelemetry.scope(masqueTelemetryUnscopedKey))

	if _, err := conn.Write([]byte("header-only")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	delta := masqueTelemetryDelta(before)
	if delta["requested_sessions"] != 1 {
		t.Fatalf("requested_sessions delta = %d", delta["requested_sessions"])
	}
	if delta["read_fallback_sessions"] != 1 || delta["write_fallback_sessions"] != 1 {
		t.Fatalf("unexpected fallback deltas: read=%d write=%d", delta["read_fallback_sessions"], delta["write_fallback_sessions"])
	}
	if delta["datagram_read_enabled_sessions"] != 0 || delta["datagram_write_enabled_sessions"] != 0 {
		t.Fatalf("unexpected datagram enable deltas: read=%d write=%d", delta["datagram_read_enabled_sessions"], delta["datagram_write_enabled_sessions"])
	}
}

func TestMASQUEConnDatagramReadPreservesReceiveOrder(t *testing.T) {
	stream := &fakeMASQUEStream{
		ctx: context.Background(),
		datagramReads: [][]byte{
			[]byte("pkt-2"),
			[]byte("pkt-1"),
		},
	}
	conn := newMASQUEConn(stream, nil, nil, nil, false, globalMASQUETelemetry.scope(masqueTelemetryUnscopedKey))

	if err := conn.EnableTransportDatagramRead(); err != nil {
		t.Fatal(err)
	}

	first := make([]byte, len("pkt-2"))
	if _, err := io.ReadFull(conn, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "pkt-2" {
		t.Fatalf("unexpected first datagram: %q", string(first))
	}

	second := make([]byte, len("pkt-1"))
	if _, err := io.ReadFull(conn, second); err != nil {
		t.Fatal(err)
	}
	if string(second) != "pkt-1" {
		t.Fatalf("unexpected second datagram: %q", string(second))
	}
}

func TestMASQUEConnDatagramReadHandlesLossWithoutCorruption(t *testing.T) {
	stream := &fakeMASQUEStream{
		ctx: context.Background(),
		datagramReads: [][]byte{
			[]byte("pkt-1"),
			[]byte("pkt-3"),
		},
	}
	conn := newMASQUEConn(stream, nil, nil, nil, false, globalMASQUETelemetry.scope(masqueTelemetryUnscopedKey))

	if err := conn.EnableTransportDatagramRead(); err != nil {
		t.Fatal(err)
	}

	firstChunk := make([]byte, 2)
	if _, err := io.ReadFull(conn, firstChunk); err != nil {
		t.Fatal(err)
	}
	if string(firstChunk) != "pk" {
		t.Fatalf("unexpected first chunk: %q", string(firstChunk))
	}

	firstTail := make([]byte, len("pkt-1")-2)
	if _, err := io.ReadFull(conn, firstTail); err != nil {
		t.Fatal(err)
	}
	if string(firstTail) != "t-1" {
		t.Fatalf("unexpected first tail: %q", string(firstTail))
	}

	second := make([]byte, len("pkt-3"))
	if _, err := io.ReadFull(conn, second); err != nil {
		t.Fatal(err)
	}
	if string(second) != "pkt-3" {
		t.Fatalf("unexpected second datagram: %q", string(second))
	}
}

func TestMASQUETelemetryTracksPerOutboundBreakdown(t *testing.T) {
	const outboundKey = "proxy-a"

	beforeGlobal := globalMASQUETelemetry.globalSnapshot()
	beforeOutbound := globalMASQUETelemetry.outboundSnapshotFor(outboundKey)
	beforeUnscoped := globalMASQUETelemetry.outboundSnapshotFor(masqueTelemetryUnscopedKey)

	stream := &fakeMASQUEStream{
		ctx: context.Background(),
		datagramReads: [][]byte{
			[]byte("reply"),
		},
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Tag:  outboundKey,
		Name: "trojan",
	}})
	conn := newMASQUEConn(stream, nil, nil, nil, true, globalMASQUETelemetry.scope(masqueTelemetryOutboundKeyFromContext(ctx)))

	if err := conn.EnableTransportDatagramWrite(); err != nil {
		t.Fatal(err)
	}
	if err := conn.EnableTransportDatagramRead(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("reply"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	globalDelta := masqueTelemetryDelta(beforeGlobal)
	outboundDelta := masqueOutboundTelemetryDelta(outboundKey, beforeOutbound)
	unscopedDelta := masqueOutboundTelemetryDelta(masqueTelemetryUnscopedKey, beforeUnscoped)

	if globalDelta["requested_sessions"] != 1 {
		t.Fatalf("unexpected global requested_sessions delta: %d", globalDelta["requested_sessions"])
	}
	if outboundDelta["requested_sessions"] != 1 {
		t.Fatalf("unexpected outbound requested_sessions delta: %d", outboundDelta["requested_sessions"])
	}
	if outboundDelta["bidirectional_datagram_sessions"] != 1 {
		t.Fatalf("unexpected outbound bidirectional_datagram_sessions delta: %d", outboundDelta["bidirectional_datagram_sessions"])
	}
	if outboundDelta["datagram_write_packets"] != 1 || outboundDelta["datagram_read_packets"] != 1 {
		t.Fatalf("unexpected outbound datagram packet deltas: write=%d read=%d", outboundDelta["datagram_write_packets"], outboundDelta["datagram_read_packets"])
	}
	if unscopedDelta["requested_sessions"] != 0 || unscopedDelta["bidirectional_datagram_sessions"] != 0 {
		t.Fatalf("unexpected unscoped telemetry delta: requested=%d bidirectional=%d", unscopedDelta["requested_sessions"], unscopedDelta["bidirectional_datagram_sessions"])
	}
}
