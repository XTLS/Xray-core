package splithttp

import (
	"testing"
	"time"
)

func TestDownlinkBufferSplitsSegments(t *testing.T) {
	d := newDownlinkBuffer(1 << 20)
	d.Write([]byte("0123456789"))
	want := []string{"0123", "4567", "89"}
	for i, w := range want {
		seg, eof := d.TakeSegment(4, time.Second, 10*time.Millisecond)
		if eof || string(seg) != w {
			t.Fatalf("сегмент %d: получили %q eof=%v, ждали %q", i, seg, eof, w)
		}
	}
}

func TestDownlinkBufferIdleReturnsEmpty(t *testing.T) {
	d := newDownlinkBuffer(1 << 20)
	seg, eof := d.TakeSegment(4, 50*time.Millisecond, 10*time.Millisecond)
	if len(seg) != 0 || eof {
		t.Fatalf("ждали пустой сегмент без eof, получили %q eof=%v", seg, eof)
	}
}

func TestDownlinkBufferCloseDrainsThenEOF(t *testing.T) {
	d := newDownlinkBuffer(1 << 20)
	d.Write([]byte("ab"))
	d.Close()
	if seg, eof := d.TakeSegment(4, time.Second, 10*time.Millisecond); string(seg) != "ab" || eof {
		t.Fatalf("после Close ждали остаток \"ab\", получили %q eof=%v", seg, eof)
	}
	if _, eof := d.TakeSegment(4, time.Second, 10*time.Millisecond); !eof {
		t.Fatal("ждали eof после опустошения закрытого буфера")
	}
}
