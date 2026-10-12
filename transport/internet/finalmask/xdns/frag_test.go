package xdns

import (
	"bytes"
	"testing"
	"time"
)

func TestFragmentsReassembleOnlyCompleteCurrentGroup(t *testing.T) {
	m := NewFragManager()
	defer m.Close()
	key := FragKey{clientID: ClientID{1}, fragID: 255}
	buf := make([]byte, fragSize)
	if m.Feed(buf, key, 1, 3, []byte("b")) != 0 {
		t.Fatal("incomplete group was delivered")
	}
	if m.Feed(buf, key, 1, 3, []byte("duplicate")) != 0 {
		t.Fatal("duplicate fragment was delivered")
	}
	if m.Feed(buf, key, 0, 2, []byte("changed count")) != 0 {
		t.Fatal("changed fragment count was accepted")
	}
	if m.Feed(buf, key, 3, 3, []byte("out of range")) != 0 {
		t.Fatal("out-of-range fragment was accepted")
	}
	if m.Feed(buf, key, 2, 3, []byte("c")) != 0 {
		t.Fatal("missing first fragment was delivered")
	}
	if n := m.Feed(buf, key, 0, 3, []byte("a")); n != 3 || string(buf[:n]) != "abc" {
		t.Fatalf("out-of-order reassembly: %d %q", n, buf[:n])
	}
	if m.Feed(buf, key, 0, 2, []byte("stale")) != 0 {
		t.Fatal("incomplete reused ID was delivered")
	}
	m.mu.Lock()
	m.m[key].deadline = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if m.Feed(buf, key, 1, 2, []byte("fresh")) != 0 {
		t.Fatal("expired fragment was delivered")
	}
	if n := m.Feed(buf, key, 0, 2, []byte("new")); n != 8 || string(buf[:n]) != "newfresh" {
		t.Fatalf("expired group was retained: %d %q", n, buf[:n])
	}
}

func TestFragmentsSizeAndClientBoundaries(t *testing.T) {
	m := NewFragManager()
	defer m.Close()
	buf := make([]byte, fragSize)
	key := FragKey{clientID: ClientID{1}, fragID: 0}
	other := FragKey{clientID: ClientID{2}, fragID: 0}
	part := bytes.Repeat([]byte{255}, fragSize/2)
	if m.Feed(buf, key, 0, 2, part) != 0 || m.Feed(buf, other, 1, 2, part) != 0 {
		t.Fatal("fragments from different clients were joined")
	}
	if n := m.Feed(buf, key, 1, 2, part); n != fragSize || !bytes.Equal(buf[:n], append(append([]byte(nil), part...), part...)) {
		t.Fatal("4096-byte boundary failed")
	}
	key.fragID++
	m.Feed(buf, key, 0, 2, bytes.Repeat([]byte{1}, fragSize))
	if m.Feed(buf, key, 1, 2, []byte{2}) != 0 {
		t.Fatal("oversized group was delivered")
	}
}
