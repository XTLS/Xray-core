package protocol_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/common/protocol"
)

func TestMemoryUserCancel(t *testing.T) {
	u := &MemoryUser{Email: "a@test"}
	ctx := u.Context()
	if ctx.Err() != nil {
		t.Fatal("context is done before Cancel")
	}
	u.Cancel()
	if ctx.Err() == nil {
		t.Fatal("context is not done after Cancel")
	}
	u.Cancel()
	if u.Context() != ctx {
		t.Fatal("Context changed after Cancel")
	}
}

func TestMemoryUserCancelFirst(t *testing.T) {
	u := &MemoryUser{}
	u.Cancel()
	if u.Context().Err() == nil {
		t.Fatal("context is not done after Cancel")
	}
	// A connection that binds after the user was removed closes at once.
	fired := make(chan struct{})
	context.AfterFunc(u.Context(), func() { close(fired) })
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("binding made after Cancel did not fire")
	}
}

func TestMemoryUserStoppedBinding(t *testing.T) {
	u := &MemoryUser{}
	fired := make(chan struct{}, 1)
	for range 1000 {
		stop := context.AfterFunc(u.Context(), func() {
			select {
			case fired <- struct{}{}:
			default:
			}
		})
		if !stop() {
			t.Fatal("binding could not be stopped")
		}
	}
	u.Cancel()
	select {
	case <-fired:
		t.Fatal("stopped binding fired")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestMemoryUserDerive(t *testing.T) {
	u := &MemoryUser{Email: "a@test", Level: 1}
	d := u.Derive(nil)
	if d.Email != u.Email || d.Level != u.Level {
		t.Fatal("derived user lost email or level")
	}
	if d.Context() != u.Context() {
		t.Fatal("derived user has its own context")
	}
	d.Cancel()
	if u.Context().Err() != nil {
		t.Fatal("Cancel on a derived user canceled the original")
	}
	u.Cancel()
	if d.Context().Err() == nil {
		t.Fatal("derived user's context is not done after the original's Cancel")
	}
}

func TestMemoryUserEqualIgnoresContext(t *testing.T) {
	u := &MemoryUser{Email: "a@test", Level: 1}
	u.Cancel()
	if !cmp.Equal(u, &MemoryUser{Email: "a@test", Level: 1}) {
		t.Fatal("users that differ only in their context are not equal")
	}
	if cmp.Equal(u, &MemoryUser{Email: "b@test", Level: 1}) {
		t.Fatal("users with different emails are equal")
	}
}
