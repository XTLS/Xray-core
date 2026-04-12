// Package connectiontracker provides a thread-safe registry of active proxy
// connections. It enables forced per-user disconnection and exposes real-time
// per-connection metadata and traffic statistics for API consumers.
package connectiontracker

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ConnEntry holds metadata and traffic state for a single tracked connection.
type ConnEntry struct {
	Email        string
	InboundTag   string
	Protocol     string
	Cancel       context.CancelFunc
	StartTime    time.Time
	lastActivity int64 // atomic, Unix nanosecond timestamp
	uplink       int64 // atomic, bytes received from client
	downlink     int64 // atomic, bytes sent to client
}

// ConnectionInfo is a read-only snapshot of an active connection's state.
type ConnectionInfo struct {
	ID           uint32
	Email        string
	InboundTag   string
	Protocol     string
	StartTime    time.Time
	LastActivity time.Time
	Uplink       int64
	Downlink     int64
}

// Manager holds the shared connection registry and subscription fan-out for
// a single Xray instance.
type Manager struct {
	globalNext uint32

	globalMu sync.Mutex
	trackers []*Tracker

	subMu       sync.Mutex
	subscribers []chan WatchEvent
}

// Tracker tracks active connections per user, enabling forced disconnection
// and real-time connection inspection.
type Tracker struct {
	manager *Manager

	mu    sync.Mutex
	conns map[string]map[uint32]*ConnEntry // [email][id] -> entry
	byID  map[uint32]*ConnEntry            // flat index for O(1) lookup by ID
}

// WatchEvent is delivered to subscribers whenever a connection opens or closes.
type WatchEvent struct {
	Connected bool // true = opened, false = closed
	Info      ConnectionInfo
}

// NewManager creates an empty tracker manager.
func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) snapshotTrackers() []*Tracker {
	m.globalMu.Lock()
	trackers := make([]*Tracker, len(m.trackers))
	copy(trackers, m.trackers)
	m.globalMu.Unlock()
	return trackers
}

// Subscribe returns a channel that receives WatchEvents. Call Unsubscribe when
// done to avoid a goroutine / channel leak.
func (m *Manager) Subscribe() chan WatchEvent {
	ch := make(chan WatchEvent, 64)
	m.subMu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.subMu.Unlock()
	return ch
}

// Unsubscribe removes a channel returned by Subscribe.
func (m *Manager) Unsubscribe(ch chan WatchEvent) {
	m.subMu.Lock()
	defer m.subMu.Unlock()

	for i, s := range m.subscribers {
		if s == ch {
			m.subscribers[i] = m.subscribers[len(m.subscribers)-1]
			m.subscribers = m.subscribers[:len(m.subscribers)-1]
			return
		}
	}
}

func (m *Manager) emit(ev WatchEvent) {
	m.subMu.Lock()
	subs := make([]chan WatchEvent, len(m.subscribers))
	copy(subs, m.subscribers)
	m.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default: // drop if subscriber is too slow
		}
	}
}

// NewTracker creates a new, empty Tracker and registers it in the manager so
// that ListAllConnections and CloseGlobalConn can see its connections.
func (m *Manager) NewTracker() *Tracker {
	t := &Tracker{
		manager: m,
		conns:   make(map[string]map[uint32]*ConnEntry),
		byID:    make(map[uint32]*ConnEntry),
	}
	m.globalMu.Lock()
	m.trackers = append(m.trackers, t)
	m.globalMu.Unlock()
	return t
}

// New creates an isolated Tracker backed by its own Manager. It is kept for
// standalone use and tests; production components should acquire a Manager
// through Xray features and call NewTracker on it.
func New() *Tracker {
	return NewManager().NewTracker()
}

func disconnectInfo(id uint32, entry *ConnEntry) ConnectionInfo {
	return ConnectionInfo{
		ID:           id,
		Email:        entry.Email,
		InboundTag:   entry.InboundTag,
		Protocol:     entry.Protocol,
		StartTime:    entry.StartTime,
		LastActivity: time.Unix(0, atomic.LoadInt64(&entry.lastActivity)),
		Uplink:       atomic.LoadInt64(&entry.uplink),
		Downlink:     atomic.LoadInt64(&entry.downlink),
	}
}

// ListAllConnections returns a snapshot of every active connection across all
// Tracker instances that were created by NewTracker.
func (m *Manager) ListAllConnections() []ConnectionInfo {
	ts := m.snapshotTrackers()
	var all []ConnectionInfo
	for _, t := range ts {
		all = append(all, t.ListConnections()...)
	}
	return all
}

// GetUserStats returns the aggregate uplink bytes, downlink bytes, and active
// connection count for email across all registered Trackers.
func (m *Manager) GetUserStats(email string) (uplink, downlink int64, connCount int32) {
	ts := m.snapshotTrackers()
	for _, t := range ts {
		t.mu.Lock()
		for _, e := range t.conns[email] {
			uplink += atomic.LoadInt64(&e.uplink)
			downlink += atomic.LoadInt64(&e.downlink)
			connCount++
		}
		t.mu.Unlock()
	}
	return
}

// CloseGlobalConn closes the connection with the given ID in whichever Tracker
// owns it. Returns true if the connection was found and cancelled.
func (m *Manager) CloseGlobalConn(id uint32) bool {
	ts := m.snapshotTrackers()
	for _, t := range ts {
		if t.CloseConn(id) {
			return true
		}
	}
	return false
}

// Register records a connection's cancel function under email and returns its
// ID. Use RegisterWithMeta for richer per-connection tracking.
func (t *Tracker) Register(email string, cancel context.CancelFunc) uint32 {
	id, _ := t.RegisterWithMeta(email, cancel, "", "")
	return id
}

// RegisterWithMeta records a connection with full metadata and returns the
// connection ID and a *ConnEntry whose traffic counters can be updated by
// passing it to WrapConn.
func (t *Tracker) RegisterWithMeta(email string, cancel context.CancelFunc, inboundTag, protocol string) (uint32, *ConnEntry) {
	now := time.Now()
	entry := &ConnEntry{
		Email:      email,
		InboundTag: inboundTag,
		Protocol:   protocol,
		Cancel:     cancel,
		StartTime:  now,
	}
	atomic.StoreInt64(&entry.lastActivity, now.UnixNano())
	id := atomic.AddUint32(&t.manager.globalNext, 1)
	t.mu.Lock()
	if t.conns[email] == nil {
		t.conns[email] = make(map[uint32]*ConnEntry)
	}
	t.conns[email][id] = entry
	t.byID[id] = entry
	t.mu.Unlock()
	t.manager.emit(WatchEvent{Connected: true, Info: ConnectionInfo{
		ID:           id,
		Email:        email,
		InboundTag:   inboundTag,
		Protocol:     protocol,
		StartTime:    now,
		LastActivity: now,
	}})
	return id, entry
}

// Unregister removes a connection from the tracker when it closes naturally.
func (t *Tracker) Unregister(email string, id uint32) {
	t.mu.Lock()
	entry := t.byID[id]
	delete(t.byID, id)
	if m := t.conns[email]; m != nil {
		delete(m, id)
		if len(m) == 0 {
			delete(t.conns, email)
		}
	}
	t.mu.Unlock()
	if entry != nil {
		t.manager.emit(WatchEvent{Connected: false, Info: ConnectionInfo{
			ID:         id,
			Email:      entry.Email,
			InboundTag: entry.InboundTag,
			Protocol:   entry.Protocol,
			StartTime:  entry.StartTime,
		}})
	}
}

// CancelAll cancels every active connection belonging to email.
func (t *Tracker) CancelAll(email string) {
	t.mu.Lock()
	entries := t.conns[email]
	delete(t.conns, email)

	type closingConn struct {
		id    uint32
		entry *ConnEntry
	}
	closing := make([]closingConn, 0, len(entries))

	for id, entry := range entries {
		delete(t.byID, id)
		closing = append(closing, closingConn{id: id, entry: entry})
	}
	t.mu.Unlock()

	for _, c := range closing {
		t.manager.emit(WatchEvent{
			Connected: false,
			Info:      disconnectInfo(c.id, c.entry),
		})
		c.entry.Cancel()
	}
}

// CloseConn cancels the connection identified by id.
// Returns true if the connection was found and cancelled.
func (t *Tracker) CloseConn(id uint32) bool {
	t.mu.Lock()
	entry, ok := t.byID[id]
	if ok {
		delete(t.byID, id)
		if m := t.conns[entry.Email]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(t.conns, entry.Email)
			}
		}
	}
	t.mu.Unlock()

	if ok {
		t.manager.emit(WatchEvent{
			Connected: false,
			Info:      disconnectInfo(id, entry),
		})
		entry.Cancel()
	}
	return ok
}

// GetConnCount returns the number of active connections for email.
func (t *Tracker) GetConnCount(email string) int {
	t.mu.Lock()
	n := len(t.conns[email])
	t.mu.Unlock()
	return n
}

// ListConnections returns a snapshot of all currently active connections.
func (t *Tracker) ListConnections() []ConnectionInfo {
	t.mu.Lock()
	result := make([]ConnectionInfo, 0, len(t.byID))
	for id, entry := range t.byID {
		result = append(result, ConnectionInfo{
			ID:           id,
			Email:        entry.Email,
			InboundTag:   entry.InboundTag,
			Protocol:     entry.Protocol,
			StartTime:    entry.StartTime,
			LastActivity: time.Unix(0, atomic.LoadInt64(&entry.lastActivity)),
			Uplink:       atomic.LoadInt64(&entry.uplink),
			Downlink:     atomic.LoadInt64(&entry.downlink),
		})
	}
	t.mu.Unlock()
	return result
}

// TrackedConn wraps a stat.Connection and records per-connection traffic
// counters into the associated ConnEntry. Obtain one via WrapConn.
type TrackedConn struct {
	stat.Connection
	entry *ConnEntry
}

func (c *TrackedConn) Read(b []byte) (int, error) {
	n, err := c.Connection.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.entry.uplink, int64(n))
		atomic.StoreInt64(&c.entry.lastActivity, time.Now().UnixNano())
	}
	return n, err
}

func (c *TrackedConn) Write(b []byte) (int, error) {
	n, err := c.Connection.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.entry.downlink, int64(n))
		atomic.StoreInt64(&c.entry.lastActivity, time.Now().UnixNano())
	}
	return n, err
}

// WrapConn wraps conn so that every Read and Write updates the traffic
// counters in entry. Call after RegisterWithMeta to enable byte-level tracking.
func WrapConn(conn stat.Connection, entry *ConnEntry) stat.Connection {
	return &TrackedConn{Connection: conn, entry: entry}
}

// TrackedPacketConn wraps an N.PacketConn (UDP) and records per-connection
// traffic counters into the associated ConnEntry.
type TrackedPacketConn struct {
	N.PacketConn
	entry *ConnEntry
}

func (c *TrackedPacketConn) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	addr, err := c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer.Len() > 0 {
		atomic.AddInt64(&c.entry.uplink, int64(buffer.Len()))
		atomic.StoreInt64(&c.entry.lastActivity, time.Now().UnixNano())
	}
	return addr, err
}

func (c *TrackedPacketConn) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	n := buffer.Len()
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil && n > 0 {
		atomic.AddInt64(&c.entry.downlink, int64(buffer.Len()))
		atomic.StoreInt64(&c.entry.lastActivity, time.Now().UnixNano())
	}
	return err
}

// WrapPacketConn wraps a UDP PacketConn so that every ReadPacket and WritePacket
// updates the traffic counters in entry. Call after RegisterWithMeta to enable
// byte-level tracking for UDP connections.
func WrapPacketConn(conn N.PacketConn, entry *ConnEntry) N.PacketConn {
	return &TrackedPacketConn{PacketConn: conn, entry: entry}
}
