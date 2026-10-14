package inbound

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func sessionTestUser(email, id string) *protocol.MemoryUser {
	parsed, err := uuid.ParseString(id)
	if err != nil {
		panic(err)
	}
	return &protocol.MemoryUser{Email: email, Account: &vless.MemoryAccount{ID: protocol.NewID(parsed)}}
}

func TestRemovalClosesOnlyRevokedUsersSessions(t *testing.T) {
	h := &Handler{validator: new(vless.MemoryValidator)}
	a := sessionTestUser("a@example.test", "00000000-0000-4000-8000-000000000001")
	b := sessionTestUser("b@example.test", "00000000-0000-4000-8000-000000000002")
	for _, u := range []*protocol.MemoryUser{a, b} {
		if err := h.AddUser(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	aConn, aPeer := net.Pipe()
	defer aConn.Close()
	defer aPeer.Close()
	bConn, bPeer := net.Pipe()
	defer bConn.Close()
	defer bPeer.Close()
	aCtx, aRelease, err := h.trackUserSession(context.Background(), a, aConn)
	if err != nil {
		t.Fatal(err)
	}
	defer aRelease()
	bCtx, bRelease, err := h.trackUserSession(context.Background(), b, bConn)
	if err != nil {
		t.Fatal(err)
	}
	defer bRelease()
	if err := h.RevokeUserSessions(context.Background(), "A@example.test"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-aCtx.Done():
	default:
		t.Fatal("revoked context remains active")
	}
	select {
	case <-bCtx.Done():
		t.Fatal("unrelated context cancelled")
	default:
	}
	_ = aPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := aPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked session remains open")
	}
	if _, _, err := h.trackUserSession(context.Background(), a, aConn); err == nil {
		t.Fatal("revoked authentication admitted")
	}
	replacement := sessionTestUser(a.Email, "00000000-0000-4000-8000-000000000001")
	if err := h.AddUser(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.trackUserSession(context.Background(), a, aConn); err == nil {
		t.Fatal("stale authentication admitted after re-add")
	}
	ctx, release, err := h.trackUserSession(context.Background(), replacement, bConn)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if ctx.Err() == nil {
		t.Fatal("session cleanup failed")
	}
	bRelease()
	aRelease()
	if len(h.userSessions) != 0 {
		t.Fatal("session registry leaked")
	}
}
