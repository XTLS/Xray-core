package account

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func newUser(auth, email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{Auth: auth}}
}

func TestRemovedUserConnectionsAreClosed(t *testing.T) {
	v := NewValidator()
	if err := v.Add(newUser("pw-1", "u1")); err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	untrack := v.Track("pw-1", func() { closed.Add(1) })
	defer untrack()

	if err := v.DelByEmail("u1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(removeGrace + 500*time.Millisecond)
	if closed.Load() != 1 {
		t.Fatalf("connection of a removed user was not closed (closed=%d)", closed.Load())
	}
}

func TestReAddedUserConnectionsStayOpen(t *testing.T) {
	v := NewValidator()
	if err := v.Add(newUser("pw-1", "u1")); err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	untrack := v.Track("pw-1", func() { closed.Add(1) })
	defer untrack()

	// An update applied as remove + add with the same auth.
	if err := v.DelByEmail("u1"); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(newUser("pw-1", "u1")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(removeGrace + 500*time.Millisecond)
	if closed.Load() != 0 {
		t.Fatalf("connection of a re-added user was closed (closed=%d)", closed.Load())
	}
}

func TestUntrackedConnectionIsNotClosed(t *testing.T) {
	v := NewValidator()
	if err := v.Add(newUser("pw-1", "u1")); err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	untrack := v.Track("pw-1", func() { closed.Add(1) })
	untrack()

	if err := v.DelByEmail("u1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(removeGrace + 500*time.Millisecond)
	if closed.Load() != 0 {
		t.Fatalf("an ended connection was closed again (closed=%d)", closed.Load())
	}
}
