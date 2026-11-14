package xdrive

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

func announceEntry(name string) string {
	return strings.TrimPrefix(name, sessionsDir+"/")
}

func TestAcceptPendingClientClockBehind(t *testing.T) {
	l := newTestListener(t, t.TempDir())
	var conns int
	l.addConn = func(c stat.Connection) { conns++; c.Close() }
	ctx := context.Background()

	session := "clockbehind"
	ring := sessionPrefix(session) + "/" + uplinkDir + "/s0"
	if err := l.storage.Put(ctx, ring, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// The client's clock is ten minutes behind the server's.
	name := announceName(session, time.Now().Add(-10*time.Minute))
	if err := l.storage.Put(ctx, name, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	accepted, err := l.acceptPending(ctx)
	if err != nil || !accepted {
		t.Fatalf("a slow client clock must not drop the session: accepted=%v err=%v", accepted, err)
	}
	if conns != 1 {
		t.Fatalf("addConn called %d times, want 1", conns)
	}
	if _, err := l.storage.Get(ctx, ring); err != nil {
		t.Fatalf("the ring of an accepted session was dropped: %v", err)
	}
}

func TestAcceptPendingStaleLeftoverProtectsActiveRing(t *testing.T) {
	l := newTestListener(t, t.TempDir())
	l.params.sessionTTL = 50 * time.Millisecond
	var conns int
	l.addConn = func(c stat.Connection) { conns++; c.Close() }
	ctx := context.Background()

	session := "active"
	l.active[session] = true
	l.handled[session] = time.Now()
	ring := sessionPrefix(session) + "/" + uplinkDir + "/s0"
	if err := l.storage.Put(ctx, ring, []byte("x")); err != nil {
		t.Fatal(err)
	}
	name := announceName(session, time.Now())
	if err := l.storage.Put(ctx, name, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	// The listener first saw this leftover entry long ago on its own clock.
	l.firstSeen = map[string]time.Time{announceEntry(name): time.Now().Add(-time.Hour)}

	accepted, err := l.acceptPending(ctx)
	if err != nil || accepted {
		t.Fatalf("a stale leftover must not be accepted: accepted=%v err=%v", accepted, err)
	}
	if conns != 0 {
		t.Fatalf("addConn called %d times, want 0", conns)
	}
	waitFor(t, "the leftover announcement file to drop", func() bool {
		_, err := l.storage.Get(ctx, name)
		return err == errNotFound
	})
	if _, err := l.storage.Get(ctx, ring); err != nil {
		t.Fatalf("the ring of an active session was dropped: %v", err)
	}
}

func TestAcceptPendingTrulyLeftoverDropped(t *testing.T) {
	l := newTestListener(t, t.TempDir())
	l.params.sessionTTL = 50 * time.Millisecond
	var conns int
	l.addConn = func(c stat.Connection) { conns++; c.Close() }
	ctx := context.Background()

	session := "leftover"
	ring := sessionPrefix(session) + "/" + uplinkDir + "/s0"
	if err := l.storage.Put(ctx, ring, []byte("x")); err != nil {
		t.Fatal(err)
	}
	name := announceName(session, time.Now())
	if err := l.storage.Put(ctx, name, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	l.firstSeen = map[string]time.Time{announceEntry(name): time.Now().Add(-time.Hour)}

	accepted, err := l.acceptPending(ctx)
	if err != nil || accepted {
		t.Fatalf("accepted=%v err=%v", accepted, err)
	}
	waitFor(t, "the leftover announcement and ring to drop", func() bool {
		_, e1 := l.storage.Get(ctx, name)
		_, e2 := l.storage.Get(ctx, ring)
		return e1 == errNotFound && e2 == errNotFound
	})
}

func TestAcceptPendingPrunesFirstSeen(t *testing.T) {
	l := newTestListener(t, t.TempDir())
	l.addConn = func(c stat.Connection) { c.Close() }
	ctx := context.Background()
	l.firstSeen = map[string]time.Time{"gone-entry": time.Now()}
	if _, err := l.acceptPending(ctx); err != nil {
		t.Fatal(err)
	}
	if _, still := l.firstSeen["gone-entry"]; still {
		t.Fatal("firstSeen kept an entry that is no longer listed")
	}
}
