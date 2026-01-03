package xpool_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/xpool"
)

type MockWriter struct {
	Buf bytes.Buffer
}

func (w *MockWriter) Write(p []byte) (int, error) {
	return w.Buf.Write(p)
}

type MockSession struct {
	ID  uint32
	Seq uint32
	Ack uint32
}

func (s *MockSession) GetID() uint32 { return s.ID }
func (s *MockSession) GetNextSeq() uint32 {
	seq := s.Seq
	s.Seq++
	return seq
}
func (s *MockSession) GetAck() uint32 { return s.Ack }
func (s *MockSession) UpdateAck(seq uint32) {
	if seq > s.Ack {
		s.Ack = seq
	}
}

func TestXPoolWriter(t *testing.T) {
	mw := &MockWriter{}
	sb := xpool.NewSendBuffer(10)
	sess := &MockSession{ID: 100, Seq: 0, Ack: 50}

	w := xpool.NewXPoolWriter(mw, sb, sess)

	payloadData := []byte("Payload")
	b := buf.New()
	b.Write(payloadData)

	mb := buf.MultiBuffer{b}

	if err := w.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	out := mw.Buf.Bytes()
	if len(out) < 7 {
		t.Errorf("Output too short: %d", len(out))
	}

	reader := bytes.NewReader(out)
	sr := xpool.NewSegmentReader(reader)
	seg, err := sr.ReadSegment()
	if err != nil {
		t.Fatalf("ReadSegment failed: %v", err)
	}

	if seg.SID != 100 {
		t.Errorf("SID=%d, want 100", seg.SID)
	}
	if seg.Seq != 0 {
		t.Errorf("Seq=%d, want 0", seg.Seq)
	}
	if seg.Ack != 50 {
		t.Errorf("Ack=%d, want 50", seg.Ack)
	}
	if string(seg.Payload.Bytes()) != "Payload" {
		t.Errorf("Payload=%s", seg.Payload.String())
	}

	unacked := sb.GetUnacked()
	if len(unacked) != 1 {
		t.Errorf("SendBuffer count %d", len(unacked))
	} else {
		entry := unacked[0]
		if entry.Seq != 0 {
			t.Errorf("Stored Seq=%d, want 0", entry.Seq)
		}
		// Payload length check
		// Original payload was 7 bytes ("Payload").
		// Header was prepended. Then Advance was called.
		// So Buffer in SendBuffer should point to Payload.
		// Len should be 7.
		if entry.Buffer.Len() != 7 {
			t.Errorf("Stored buffer len %d, want 7", entry.Buffer.Len())
		}
	}
}
