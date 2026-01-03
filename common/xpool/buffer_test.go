package xpool_test

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/xpool"
)

func TestSendBuffer(t *testing.T) {
	sb := xpool.NewSendBuffer(3)

	b1 := buf.New()
	b2 := buf.New()
	b3 := buf.New()
	b4 := buf.New()

	if !sb.Add(1, b1) {
		t.Error("Failed to add b1")
	}
	if !sb.Add(2, b2) {
		t.Error("Failed to add b2")
	}
	if !sb.Add(3, b3) {
		t.Error("Failed to add b3")
	}

	if sb.Add(4, b4) {
		t.Error("Should be full")
	}

	unacked := sb.GetUnacked()
	if len(unacked) != 3 {
		t.Errorf("Unacked len = %d, want 3", len(unacked))
	}
	if unacked[0].Buffer != b1 {
		t.Error("Buffer mismatch 1")
	}
    if unacked[0].Seq != 1 {
        t.Errorf("Seq mismatch 1: got %v", unacked[0].Seq)
    }

	n := sb.OnAck(2)
	if n != 1 {
		t.Errorf("Released %d, want 1", n)
	}

	unacked = sb.GetUnacked()
	if len(unacked) != 2 {
		t.Errorf("Unacked len = %d, want 2", len(unacked))
	}
    if unacked[0].Seq != 2 {
        t.Errorf("First unacked should be 2, got %v", unacked[0].Seq)
    }

	n = sb.OnAck(10)
	if n != 2 {
		t.Errorf("Released %d, want 2", n)
	}

	if len(sb.GetUnacked()) != 0 {
		t.Error("Should be empty")
	}

    if !sb.Add(4, b4) {
        t.Error("Should accept b4")
    }
}
