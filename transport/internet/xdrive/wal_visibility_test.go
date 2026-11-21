package xdrive

import (
	"bytes"
	"context"
	"testing"
)

type pendingSegmentStorage struct {
	Storage
	name    string
	pending bool
}

func (s *pendingSegmentStorage) Get(ctx context.Context, name string) ([]byte, error) {
	if name == s.name && s.pending {
		s.pending = false
		return []byte{}, nil
	}
	return s.Storage.Get(ctx, name)
}

func TestWALReaderRetriesVisibleEmptySegment(t *testing.T) {
	ctx := context.Background()
	base, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := objectName("up", 0, segSuffix)
	second := objectName("up", 1, segSuffix)
	if err := base.Put(ctx, first, []byte("first record")); err != nil {
		t.Fatal(err)
	}
	if err := base.Put(ctx, second, []byte("second record")); err != nil {
		t.Fatal(err)
	}
	store := &pendingSegmentStorage{Storage: base, name: first, pending: true}
	p := paramsFromConfig(&Config{Concurrency: 2})
	r := &walReader{
		ctx: ctx, storage: store, prefix: "up", params: p,
		ch: make(chan []byte, 2), discards: make(chan string, 2),
	}

	advanced, eof, err := r.poll()
	if err != nil || advanced || eof || r.seq != 0 || len(r.ch) != 0 || len(r.discards) != 0 {
		t.Fatalf("incomplete segment consumed: advanced=%v eof=%v seq=%d queued=%d discards=%d err=%v",
			advanced, eof, r.seq, len(r.ch), len(r.discards), err)
	}

	advanced, eof, err = r.poll()
	if err != nil || !advanced || eof || r.seq != 2 {
		t.Fatalf("completed segment not retried: advanced=%v eof=%v seq=%d err=%v", advanced, eof, r.seq, err)
	}
	if !bytes.Equal(<-r.ch, []byte("first record")) || !bytes.Equal(<-r.ch, []byte("second record")) {
		t.Fatal("reader lost or reordered segment data")
	}
}
