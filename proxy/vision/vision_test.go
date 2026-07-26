package vision_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/vision"
	"github.com/xtls/xray-core/transport/pipe"
)

func uuid16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

func TestNewTrafficState_defaults(t *testing.T) {
	s := vision.NewTrafficState(uuid16("test-uuid-123456"))
	if s == nil {
		t.Fatal("expected non-nil TrafficState")
	}
	if s.NumberOfPacketToFilter != 8 {
		t.Errorf("expected NumberOfPacketToFilter=8, got %d", s.NumberOfPacketToFilter)
	}
}

func TestNewTrafficState_uuid(t *testing.T) {
	uu := uuid16("1234567890123456")
	s := vision.NewTrafficState(uu)
	if string(s.UserUUID) != string(uu) {
		t.Errorf("expected uuid %q, got %q", uu, s.UserUUID)
	}
}

func TestPaddingRoundTrip_upstream(t *testing.T) {
	content := []byte("Hello, Xray Vision!")
	pipeR, pipeW := pipe.New(pipe.WithSizeLimit(32768))

	state := vision.NewTrafficState(uuid16("uuid-123456789012"))

	w := vision.WrapWriter(pipeW, nil, state, vision.DirectionUpstream, context.Background(), nil)
	r := vision.WrapReader(pipeR, nil, state, vision.DirectionUpstream, context.Background())

	mb := buf.MultiBuffer{buf.FromBytes(content)}
	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}
	pipeW.Close()

	readMb, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	if readMb.IsEmpty() {
		t.Fatal("expected non-empty read buffer")
	}
	got := make([]byte, readMb.Len())
	readMb.Copy(got)
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestPaddingRoundTrip_downstream(t *testing.T) {
	content := []byte("Downstream payload here!")
	pipeR, pipeW := pipe.New(pipe.WithSizeLimit(32768))

	state := vision.NewTrafficState(uuid16("downstream-uuid-1"))

	w := vision.WrapWriter(pipeW, nil, state, vision.DirectionDownstream, context.Background(), nil)
	r := vision.WrapReader(pipeR, nil, state, vision.DirectionDownstream, context.Background())

	mb := buf.MultiBuffer{buf.FromBytes(content)}
	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}
	pipeW.Close()

	readMb, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	if readMb.IsEmpty() {
		t.Fatal("expected non-empty read buffer")
	}
	got := make([]byte, readMb.Len())
	readMb.Copy(got)
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestPaddingRoundTrip_bothDirections(t *testing.T) {
	upContent := []byte("uplink data")
	downContent := []byte("downlink data")

	upPipeR, upPipeW := pipe.New(pipe.WithSizeLimit(32768))
	downPipeR, downPipeW := pipe.New(pipe.WithSizeLimit(32768))

	state := vision.NewTrafficState(uuid16("pair-uuid-1234567"))

	wUp := vision.WrapWriter(upPipeW, nil, state, vision.DirectionUpstream, context.Background(), nil)
	rUp := vision.WrapReader(upPipeR, nil, state, vision.DirectionUpstream, context.Background())

	wDown := vision.WrapWriter(downPipeW, nil, state, vision.DirectionDownstream, context.Background(), nil)
	rDown := vision.WrapReader(downPipeR, nil, state, vision.DirectionDownstream, context.Background())

	mb := buf.MultiBuffer{buf.FromBytes(upContent)}
	if err := wUp.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("write upstream: %v", err)
	}
	upPipeW.Close()

	mb2 := buf.MultiBuffer{buf.FromBytes(downContent)}
	if err := wDown.WriteMultiBuffer(mb2); err != nil {
		t.Fatalf("write downstream: %v", err)
	}
	downPipeW.Close()

	readUp, err := rUp.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if !readUp.IsEmpty() {
		got := make([]byte, readUp.Len())
		readUp.Copy(got)
		if string(got) != string(upContent) {
			t.Errorf("got upstream %q, want %q", got, upContent)
		}
	}

	readDown, err := rDown.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read downstream: %v", err)
	}
	if !readDown.IsEmpty() {
		got := make([]byte, readDown.Len())
		readDown.Copy(got)
		if string(got) != string(downContent) {
			t.Errorf("got downstream %q, want %q", got, downContent)
		}
	}
}

func TestBatchedWrite(t *testing.T) {
	payloads := [][]byte{[]byte("short"), []byte("medium sized payload"), []byte("a")}
	pipeR, pipeW := pipe.New(pipe.WithSizeLimit(32768))

	state := vision.NewTrafficState(uuid16("batched-uuid-1234"))

	w := vision.WrapWriter(pipeW, nil, state, vision.DirectionUpstream, context.Background(), nil)
	r := vision.WrapReader(pipeR, nil, state, vision.DirectionUpstream, context.Background())

	mb := buf.MultiBuffer{}
	for _, p := range payloads {
		mb = append(mb, buf.FromBytes(p))
	}
	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer: %v", err)
	}
	pipeW.Close()

	readMb, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer: %v", err)
	}
	var total []byte
	for _, b := range readMb {
		total = append(total, b.Bytes()...)
	}
	want := "shortmedium sized payloada"
	if string(total) != want {
		t.Errorf("got %q, want %q", total, want)
	}
}
