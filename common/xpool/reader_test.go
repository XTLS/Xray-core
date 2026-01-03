package xpool_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/xpool"
)

func TestSegmentReader(t *testing.T) {
	flags := uint8(0x05)

	var buf bytes.Buffer
	buf.WriteByte(flags)
	buf.Write([]byte{0x00, 0x64}) // SID=100
	buf.Write([]byte{0x00, 0x0A}) // Seq=10
	buf.Write([]byte{0x00, 0x14}) // Ack=20
	buf.Write([]byte{0x00, 0x05}) // PayLen=5
	buf.Write([]byte("Hello"))

	sr := xpool.NewSegmentReader(&buf)
	seg, err := sr.ReadSegment()
	if err != nil {
		t.Fatalf("ReadSegment failed: %v", err)
	}

	if seg.SID != 100 {
		t.Errorf("SID=%v", seg.SID)
	}
	if seg.Seq != 10 {
		t.Errorf("Seq=%v", seg.Seq)
	}
	if seg.Ack != 20 {
		t.Errorf("Ack=%v", seg.Ack)
	}
	if seg.Payload == nil {
		t.Fatal("Payload is nil")
	}
	if string(seg.Payload.Bytes()) != "Hello" {
		t.Errorf("Payload=%s", seg.Payload.String())
	}
}
