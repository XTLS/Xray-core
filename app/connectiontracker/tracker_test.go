package connectiontracker_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/app/connectiontracker"
)

func TestCancelAll(t *testing.T) {
	tracker := connectiontracker.New()

	var cancelCount int32
	makeCancel := func() func() {
		return func() { atomic.AddInt32(&cancelCount, 1) }
	}

	tracker.Register("user@example.com", makeCancel())
	tracker.Register("user@example.com", makeCancel())
	tracker.Register("other@example.com", makeCancel())

	tracker.CancelAll("user@example.com")

	if got := atomic.LoadInt32(&cancelCount); got != 2 {
		t.Errorf("CancelAll: expected 2 cancels called, got %d", got)
	}
}

func TestCancelAllDoesNotAffectOtherUsers(t *testing.T) {
	tracker := connectiontracker.New()

	var otherCancelled int32
	tracker.Register("other@example.com", func() { atomic.AddInt32(&otherCancelled, 1) })

	tracker.CancelAll("user@example.com")

	if atomic.LoadInt32(&otherCancelled) != 0 {
		t.Error("CancelAll for user@example.com must not cancel other users")
	}
}

func TestUnregisterPreventsCancel(t *testing.T) {
	tracker := connectiontracker.New()

	var cancelCalled int32
	id := tracker.Register("user@example.com", func() { atomic.AddInt32(&cancelCalled, 1) })

	tracker.Unregister("user@example.com", id)
	tracker.CancelAll("user@example.com")

	if atomic.LoadInt32(&cancelCalled) != 0 {
		t.Error("cancel should not be called after Unregister")
	}
}

func TestUnregisterCleansEmptyBucket(t *testing.T) {
	tracker := connectiontracker.New()

	id := tracker.Register("user@example.com", func() {})
	tracker.Unregister("user@example.com", id)

	// Second CancelAll must be a no-op.
	tracker.CancelAll("user@example.com")
}

func TestMultipleCancelAllNoPanic(t *testing.T) {
	tracker := connectiontracker.New()

	tracker.Register("user@example.com", func() {})
	tracker.CancelAll("user@example.com")
	tracker.CancelAll("user@example.com")
}

func TestConcurrentAccess(t *testing.T) {
	tracker := connectiontracker.New()

	const goroutines = 50
	const email = "concurrent@example.com"

	var wg sync.WaitGroup
	var totalCancels int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Register(email, func() { atomic.AddInt32(&totalCancels, 1) })
		}()
	}
	wg.Wait()

	tracker.CancelAll(email)

	if got := atomic.LoadInt32(&totalCancels); got != goroutines {
		t.Errorf("concurrent: expected %d cancels, got %d", goroutines, got)
	}
}

func TestConcurrentRegisterAndCancel(t *testing.T) {
	tracker := connectiontracker.New()

	const email = "race@example.com"
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tracker.Register(email, func() {})
		}()
		go func() {
			defer wg.Done()
			tracker.CancelAll(email)
		}()
	}
	wg.Wait()
}

// --- RegisterWithMeta and extended API ---

func TestRegisterWithMetaStoresMetadata(t *testing.T) {
	tracker := connectiontracker.New()

	before := time.Now()
	id, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "inbound-tag", "vless")
	after := time.Now()

	if id == 0 {
		t.Error("expected non-zero connection ID")
	}
	if entry == nil {
		t.Fatal("expected non-nil ConnEntry")
	}
	if entry.Email != "user@example.com" {
		t.Errorf("Email: got %q, want %q", entry.Email, "user@example.com")
	}
	if entry.InboundTag != "inbound-tag" {
		t.Errorf("InboundTag: got %q, want %q", entry.InboundTag, "inbound-tag")
	}
	if entry.Protocol != "vless" {
		t.Errorf("Protocol: got %q, want %q", entry.Protocol, "vless")
	}
	if entry.StartTime.Before(before) || entry.StartTime.After(after) {
		t.Errorf("StartTime %v outside [%v, %v]", entry.StartTime, before, after)
	}
}

func TestListConnectionsReturnsAllActive(t *testing.T) {
	tracker := connectiontracker.New()

	tracker.RegisterWithMeta("alice@example.com", func() {}, "tag-a", "vmess")
	tracker.RegisterWithMeta("alice@example.com", func() {}, "tag-a", "vmess")
	tracker.RegisterWithMeta("bob@example.com", func() {}, "tag-b", "trojan")

	conns := tracker.ListConnections()
	if len(conns) != 3 {
		t.Errorf("ListConnections: got %d, want 3", len(conns))
	}
}

func TestManagerListAllConnectionsAggregatesTrackers(t *testing.T) {
	manager := connectiontracker.NewManager()
	first := manager.NewTracker()
	second := manager.NewTracker()

	first.RegisterWithMeta("alice@example.com", func() {}, "tag-a", "vmess")
	second.RegisterWithMeta("bob@example.com", func() {}, "tag-b", "trojan")

	conns := manager.ListAllConnections()
	if len(conns) != 2 {
		t.Fatalf("ListAllConnections: got %d, want 2", len(conns))
	}
}

func TestManagerGetUserStatsAggregatesTrackers(t *testing.T) {
	manager := connectiontracker.NewManager()
	first := manager.NewTracker()
	second := manager.NewTracker()

	_, firstEntry := first.RegisterWithMeta("user@example.com", func() {}, "", "")
	firstConn := connectiontracker.WrapConn(&fakeConn{readData: make([]byte, 10)}, firstEntry)
	if _, err := firstConn.Read(make([]byte, 10)); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if _, err := firstConn.Write(make([]byte, 20)); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	_, secondEntry := second.RegisterWithMeta("user@example.com", func() {}, "", "")
	secondConn := connectiontracker.WrapConn(&fakeConn{readData: make([]byte, 30)}, secondEntry)
	if _, err := secondConn.Read(make([]byte, 30)); err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if _, err := secondConn.Write(make([]byte, 40)); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	uplink, downlink, connCount := manager.GetUserStats("user@example.com")
	if uplink != 40 {
		t.Fatalf("GetUserStats uplink: got %d, want 40", uplink)
	}
	if downlink != 60 {
		t.Fatalf("GetUserStats downlink: got %d, want 60", downlink)
	}
	if connCount != 2 {
		t.Fatalf("GetUserStats connCount: got %d, want 2", connCount)
	}
}

func TestManagerCloseGlobalConnAcrossTrackers(t *testing.T) {
	manager := connectiontracker.NewManager()
	first := manager.NewTracker()
	second := manager.NewTracker()

	first.RegisterWithMeta("other@example.com", func() {}, "", "")

	var cancelled int32
	id, _ := second.RegisterWithMeta("user@example.com", func() {
		atomic.AddInt32(&cancelled, 1)
	}, "", "")

	if ok := manager.CloseGlobalConn(id); !ok {
		t.Fatal("CloseGlobalConn: expected true for existing connection")
	}
	if atomic.LoadInt32(&cancelled) != 1 {
		t.Fatal("CloseGlobalConn: cancel function was not called")
	}
}

func TestListConnectionsEmptyAfterCancelAll(t *testing.T) {
	tracker := connectiontracker.New()

	tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.CancelAll("user@example.com")

	if conns := tracker.ListConnections(); len(conns) != 0 {
		t.Errorf("expected 0 connections after CancelAll, got %d", len(conns))
	}
}

func TestListConnectionsEmptyAfterUnregister(t *testing.T) {
	tracker := connectiontracker.New()

	id, _ := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.Unregister("user@example.com", id)

	if conns := tracker.ListConnections(); len(conns) != 0 {
		t.Errorf("expected 0 connections after Unregister, got %d", len(conns))
	}
}

func TestCloseConnCancelsAndRemoves(t *testing.T) {
	tracker := connectiontracker.New()

	var cancelled int32
	id, _ := tracker.RegisterWithMeta("user@example.com", func() {
		atomic.AddInt32(&cancelled, 1)
	}, "", "")

	if ok := tracker.CloseConn(id); !ok {
		t.Error("CloseConn: expected true for existing connection")
	}
	if atomic.LoadInt32(&cancelled) != 1 {
		t.Error("CloseConn: cancel function was not called")
	}
	if len(tracker.ListConnections()) != 0 {
		t.Error("connection still present after CloseConn")
	}
}

func TestCloseConnUnknownIDReturnsFalse(t *testing.T) {
	tracker := connectiontracker.New()

	if tracker.CloseConn(999) {
		t.Error("CloseConn with unknown ID should return false")
	}
}

func TestCloseConnDoesNotAffectOtherUsers(t *testing.T) {
	tracker := connectiontracker.New()

	var otherCancelled int32
	tracker.RegisterWithMeta("other@example.com", func() {
		atomic.AddInt32(&otherCancelled, 1)
	}, "", "")

	id, _ := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.CloseConn(id)

	if atomic.LoadInt32(&otherCancelled) != 0 {
		t.Error("CloseConn must not cancel other users' connections")
	}
}

func TestGetConnCount(t *testing.T) {
	tracker := connectiontracker.New()

	tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.RegisterWithMeta("other@example.com", func() {}, "", "")

	if n := tracker.GetConnCount("user@example.com"); n != 2 {
		t.Errorf("GetConnCount: got %d, want 2", n)
	}
	if n := tracker.GetConnCount("other@example.com"); n != 1 {
		t.Errorf("GetConnCount: got %d, want 1", n)
	}
	if n := tracker.GetConnCount("nobody@example.com"); n != 0 {
		t.Errorf("GetConnCount for unknown: got %d, want 0", n)
	}
}

func TestGetConnCountDecreasesAfterUnregister(t *testing.T) {
	tracker := connectiontracker.New()

	id, _ := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.RegisterWithMeta("user@example.com", func() {}, "", "")
	tracker.Unregister("user@example.com", id)

	if n := tracker.GetConnCount("user@example.com"); n != 1 {
		t.Errorf("GetConnCount after Unregister: got %d, want 1", n)
	}
}

func TestListConnectionsMetadataFields(t *testing.T) {
	tracker := connectiontracker.New()

	tracker.RegisterWithMeta("user@example.com", func() {}, "my-tag", "trojan")

	conns := tracker.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	c := conns[0]
	if c.Email != "user@example.com" {
		t.Errorf("Email: %q", c.Email)
	}
	if c.InboundTag != "my-tag" {
		t.Errorf("InboundTag: %q", c.InboundTag)
	}
	if c.Protocol != "trojan" {
		t.Errorf("Protocol: %q", c.Protocol)
	}
	if c.ID == 0 {
		t.Error("ID must be non-zero")
	}
}

// fakeConn is a minimal net.Conn for WrapConn tests.
type fakeConn struct {
	net.Conn
	readData []byte
	readErr  error
	writeErr error
}

func (f *fakeConn) Read(b []byte) (int, error) {
	n := copy(b, f.readData)
	return n, f.readErr
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), f.writeErr
}

func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestWrapConnCountsUplinkOnRead(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	fc := &fakeConn{readData: []byte("hello world")}
	wrapped := connectiontracker.WrapConn(fc, entry)

	buf := make([]byte, 11)
	if _, err := wrapped.Read(buf); err != nil {
		t.Fatal(err)
	}

	conns := tracker.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection")
	}
	if conns[0].Uplink != 11 {
		t.Errorf("Uplink: got %d, want 11", conns[0].Uplink)
	}
	if conns[0].Downlink != 0 {
		t.Errorf("Downlink should be 0, got %d", conns[0].Downlink)
	}
}

func TestWrapConnCountsDownlinkOnWrite(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	fc := &fakeConn{}
	wrapped := connectiontracker.WrapConn(fc, entry)

	data := []byte("goodbye world")
	if _, err := wrapped.Write(data); err != nil {
		t.Fatal(err)
	}

	conns := tracker.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection")
	}
	if conns[0].Downlink != int64(len(data)) {
		t.Errorf("Downlink: got %d, want %d", conns[0].Downlink, len(data))
	}
	if conns[0].Uplink != 0 {
		t.Errorf("Uplink should be 0, got %d", conns[0].Uplink)
	}
}

func TestWrapConnUpdatesLastActivity(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	before := tracker.ListConnections()[0].LastActivity

	time.Sleep(time.Millisecond)

	fc := &fakeConn{readData: []byte("x")}
	wrapped := connectiontracker.WrapConn(fc, entry)
	buf := make([]byte, 1)
	wrapped.Read(buf) //nolint:errcheck

	after := tracker.ListConnections()[0].LastActivity
	if !after.After(before) {
		t.Errorf("LastActivity not updated: before=%v after=%v", before, after)
	}
}

// fakePacketConn is a minimal N.PacketConn for WrapPacketConn tests.
type fakePacketConn struct {
	readPacketData *B.Buffer
	readPacketErr  error
	writePacketErr error
}

func (f *fakePacketConn) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	if f.readPacketErr != nil {
		return M.Socksaddr{}, f.readPacketErr
	}
	if f.readPacketData != nil {
		buffer.Write(f.readPacketData.Bytes())
	}
	return M.Socksaddr{}, nil
}

func (f *fakePacketConn) WritePacket(buffer *B.Buffer, _ M.Socksaddr) error {
	return f.writePacketErr
}

func (f *fakePacketConn) Close() error {
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return nil
}

func (f *fakePacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (f *fakePacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (f *fakePacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestWrapPacketConnCountsUplinkOnReadPacket(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	data := B.New()
	data.Write([]byte("hello world"))

	fpc := &fakePacketConn{readPacketData: data}
	wrapped := connectiontracker.WrapPacketConn(fpc, entry)

	buf := B.New()
	defer buf.Release()
	if _, err := wrapped.ReadPacket(buf); err != nil {
		t.Fatal(err)
	}

	conns := tracker.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection")
	}
	if conns[0].Uplink != 11 {
		t.Errorf("Uplink: got %d, want 11", conns[0].Uplink)
	}
	if conns[0].Downlink != 0 {
		t.Errorf("Downlink should be 0, got %d", conns[0].Downlink)
	}
}

func TestWrapPacketConnCountsDownlinkOnWritePacket(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	fpc := &fakePacketConn{}
	wrapped := connectiontracker.WrapPacketConn(fpc, entry)

	buf := B.New()
	buf.Write([]byte("goodbye world"))
	if err := wrapped.WritePacket(buf, M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}

	conns := tracker.ListConnections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection")
	}
	if conns[0].Downlink != 13 {
		t.Errorf("Downlink: got %d, want 13", conns[0].Downlink)
	}
	if conns[0].Uplink != 0 {
		t.Errorf("Uplink should be 0, got %d", conns[0].Uplink)
	}
}

func TestWrapPacketConnUpdatesLastActivity(t *testing.T) {
	tracker := connectiontracker.New()
	_, entry := tracker.RegisterWithMeta("user@example.com", func() {}, "", "")

	before := tracker.ListConnections()[0].LastActivity

	time.Sleep(time.Millisecond)

	data := B.New()
	data.Write([]byte("x"))

	fpc := &fakePacketConn{readPacketData: data}
	wrapped := connectiontracker.WrapPacketConn(fpc, entry)
	buf := B.New()
	defer buf.Release()
	wrapped.ReadPacket(buf) //nolint:errcheck

	after := tracker.ListConnections()[0].LastActivity
	if !after.After(before) {
		t.Errorf("LastActivity not updated: before=%v after=%v", before, after)
	}
}
