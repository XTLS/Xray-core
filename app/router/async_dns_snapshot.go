package router

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const (
	asyncDNSSnapshotVersion        = 1
	asyncDNSSnapshotMaxBytes       = 8 * 1024 * 1024
	asyncDNSSnapshotMaxEntries     = 4096
	asyncDNSSnapshotStartupBudget  = 250 * time.Millisecond
	asyncDNSSnapshotShutdownBudget = 250 * time.Millisecond
	asyncDNSSnapshotInterval       = 30 * time.Second
)

// A filesystem operation cannot be canceled by Go on every filesystem. One
// shared TryLock per path prevents a slow disk from spawning another blocked
// reader/writer on each reload. Startup/Close callers still have finite budgets.
var asyncDNSSnapshotGuards sync.Map

type asyncDNSSnapshotGuard struct {
	io     sync.Mutex
	mu     sync.Mutex
	owners []*asyncDNSSnapshotStore
}
type asyncDNSSnapshotStore struct {
	path, identity string
	guard          *asyncDNSSnapshotGuard
	done           chan struct{}
	lastDirty      uint64
}

type asyncDNSSnapshotEntry struct {
	Domain          string    `json:"domain"`
	RouteRU         bool      `json:"ru"`
	Generation      string    `json:"generation"`
	FreshUntil      time.Time `json:"freshUntil"`
	HardUntil       time.Time `json:"hardUntil"`
	ServerHardUntil time.Time `json:"serverHardUntil"`
	RefreshAt       time.Time `json:"refreshAt"`
	LastUsed        time.Time `json:"lastUsed"`
}
type asyncDNSSnapshotPayload struct {
	Version  int                     `json:"version"`
	Identity string                  `json:"identity"`
	SavedAt  time.Time               `json:"savedAt"`
	Entries  []asyncDNSSnapshotEntry `json:"entries"` // MRU first
}
type asyncDNSSnapshotEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

func newAsyncDNSSnapshotStore(config *AsyncDnsRouteConfig, endpoint string, maxTTL, grace time.Duration) (*asyncDNSSnapshotStore, error) {
	path, id := config.GetSnapshotPath(), config.GetSnapshotCompatibilityId()
	if path == "" {
		return nil, nil
	}
	if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == string(filepath.Separator) {
		return nil, errors.New("async DNS snapshot requires a clean absolute file path in a dedicated directory")
	}
	if len(id) == 0 || len(id) > 256 || strings.IndexFunc(id, func(r rune) bool { return r < '!' || r > '~' }) >= 0 {
		return nil, errors.New("async DNS snapshot compatibility ID must contain 1..256 printable non-space ASCII bytes")
	}
	// Process/resolver/GeoIP namespace is supplied explicitly by the owner. The
	// endpoint and local semantics are bound here; secrets are never included.
	digest := sha256.Sum256([]byte("async-dns-v1\n" + id + "\n" + endpoint + "\n" + maxTTL.String() + "\n" + grace.String()))
	value, _ := asyncDNSSnapshotGuards.LoadOrStore(path, new(asyncDNSSnapshotGuard))
	store := &asyncDNSSnapshotStore{path: path, identity: hex.EncodeToString(digest[:]), guard: value.(*asyncDNSSnapshotGuard), done: make(chan struct{})}
	store.guard.mu.Lock()
	store.guard.owners = append(store.guard.owners, store)
	store.guard.mu.Unlock()
	return store, nil
}

func (s *asyncDNSSnapshotStore) isOwner() bool {
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	return len(s.guard.owners) > 0 && s.guard.owners[len(s.guard.owners)-1] == s
}

func (s *asyncDNSSnapshotStore) release() {
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	for i, owner := range s.guard.owners {
		if owner == s {
			s.guard.owners = append(s.guard.owners[:i], s.guard.owners[i+1:]...)
			break
		}
	}
}

func readAsyncDNSSnapshot(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > asyncDNSSnapshotMaxBytes || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("unsafe or oversized snapshot file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, asyncDNSSnapshotMaxBytes+1))
	if len(data) > asyncDNSSnapshotMaxBytes {
		return nil, errors.New("snapshot exceeds 8MiB")
	}
	return data, err
}

func decodeAsyncDNSSnapshot(data []byte, identity string, now time.Time, capacity int, maxTTL time.Duration) ([]asyncDNSSnapshotEntry, error) {
	var envelope asyncDNSSnapshotEnvelope
	if len(data) > asyncDNSSnapshotMaxBytes || json.Unmarshal(data, &envelope) != nil {
		return nil, errors.New("invalid snapshot envelope")
	}
	digest := sha256.Sum256(envelope.Payload)
	if envelope.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("snapshot checksum mismatch")
	}
	var payload asyncDNSSnapshotPayload
	if json.Unmarshal(envelope.Payload, &payload) != nil || payload.Version != asyncDNSSnapshotVersion || payload.Identity != identity || payload.SavedAt.IsZero() || now.Before(payload.SavedAt) || len(payload.Entries) > asyncDNSSnapshotMaxEntries {
		return nil, errors.New("snapshot version, context, age or entry bound mismatch")
	}
	entries := make([]asyncDNSSnapshotEntry, 0, min(capacity, len(payload.Entries)))
	seen := make(map[string]bool, len(payload.Entries))
	for _, e := range payload.Entries {
		if e.Domain == "" || len(e.Domain) > 253 || normalizeAsyncDNSDomain(e.Domain) != e.Domain || seen[e.Domain] || e.HardUntil.Before(e.FreshUntil) || e.ServerHardUntil.Before(e.HardUntil) || e.FreshUntil.After(payload.SavedAt.Add(maxTTL)) || e.LastUsed.After(payload.SavedAt) {
			return nil, errors.New("snapshot contains invalid cache metadata")
		}
		seen[e.Domain] = true
		if !now.Before(e.HardUntil) {
			continue
		}
		if len(entries) < min(capacity, asyncDNSSnapshotMaxEntries) {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func (m *AsyncDNSRouteMatcher) restoreSnapshot() {
	s := m.snapshot
	if !s.guard.io.TryLock() {
		m.stats.snapshotErrors.Add(1)
		return
	}
	result := make(chan []asyncDNSSnapshotEntry, 1)
	go func() {
		defer s.guard.io.Unlock()
		data, err := readAsyncDNSSnapshot(s.path)
		if err != nil {
			if !os.IsNotExist(err) {
				m.stats.snapshotErrors.Add(1)
			}
			result <- nil
			return
		}
		entries, err := decodeAsyncDNSSnapshot(data, s.identity, time.Now(), m.cacheCapacity, m.maxTTL)
		if err != nil {
			m.stats.snapshotErrors.Add(1)
			entries = nil
		}
		result <- entries
	}()
	select {
	case entries := <-result:
		// Loading precedes worker startup and accepting any client traffic.
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			if !time.Now().Before(e.HardUntil) {
				continue
			}
			m.putEntry(e.Domain, asyncDNSCacheEntry{routeRU: e.RouteRU, generation: e.Generation, freshUntil: e.FreshUntil, hardUntil: e.HardUntil, serverHardUntil: e.ServerHardUntil, refreshAt: e.RefreshAt, lastUsed: e.LastUsed})
		}
		m.stats.restoredEntries.Store(uint64(len(m.cache)))
		s.lastDirty = m.dirty
	case <-time.After(asyncDNSSnapshotStartupBudget):
		m.stats.snapshotErrors.Add(1)
	}
}

func (m *AsyncDNSRouteMatcher) captureSnapshot() (asyncDNSSnapshotPayload, uint64) {
	entries := make([]asyncDNSSnapshotEntry, 0, min(m.cacheCapacity, asyncDNSSnapshotMaxEntries))
	m.mu.Lock()
	defer m.mu.Unlock()
	p := asyncDNSSnapshotPayload{Version: asyncDNSSnapshotVersion, Identity: m.snapshot.identity, SavedAt: time.Now(), Entries: entries}
	for item := m.lru.Front(); item != nil && len(p.Entries) < asyncDNSSnapshotMaxEntries; item = item.Next() {
		domain := item.Value.(string)
		e := m.cache[domain]
		if !p.SavedAt.Before(e.hardUntil) {
			continue
		}
		p.Entries = append(p.Entries, asyncDNSSnapshotEntry{Domain: domain, RouteRU: e.routeRU, Generation: e.generation, FreshUntil: e.freshUntil, HardUntil: e.hardUntil, ServerHardUntil: e.serverHardUntil, RefreshAt: e.refreshAt, LastUsed: e.lastUsed})
	}
	return p, m.dirty
}

func encodeAsyncDNSSnapshot(p asyncDNSSnapshotPayload) ([]byte, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	envelope, err := json.Marshal(asyncDNSSnapshotEnvelope{Payload: data, SHA256: hex.EncodeToString(digest[:])})
	if len(envelope) > asyncDNSSnapshotMaxBytes {
		return nil, errors.New("snapshot exceeds 8MiB")
	}
	return envelope, err
}

func writeAsyncDNSSnapshot(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("snapshot parent must be a directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("snapshot target must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".dns-l1-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0o600); err == nil {
		_, err = io.Copy(f, bytes.NewReader(data))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (m *AsyncDNSRouteMatcher) persistSnapshot() {
	s := m.snapshot
	if !s.isOwner() || !s.guard.io.TryLock() {
		return
	}
	defer s.guard.io.Unlock()
	p, dirty := m.captureSnapshot()
	if dirty == s.lastDirty {
		return
	}
	data, err := encodeAsyncDNSSnapshot(p)
	if err == nil {
		err = writeAsyncDNSSnapshot(s.path, data)
	}
	if err != nil {
		m.stats.snapshotErrors.Add(1)
		return
	}
	s.lastDirty = dirty
	m.stats.snapshotWrites.Add(1)
}

func (m *AsyncDNSRouteMatcher) runSnapshotWriter() {
	defer close(m.snapshot.done)
	for {
		timer := time.NewTimer(asyncDNSSnapshotInterval + time.Duration(rand.Int64N(int64(3*time.Second))))
		select {
		case <-timer.C:
			m.persistSnapshot()
		case <-m.stop:
			timer.Stop()
			m.persistSnapshot() // best effort; Close waits only its finite budget
			return
		}
	}
}

func (m *AsyncDNSRouteMatcher) closeSnapshotWriter() {
	if m.snapshot == nil {
		return
	}
	select {
	case <-m.snapshot.done:
	case <-time.After(asyncDNSSnapshotShutdownBudget):
	}
	m.snapshot.release()
}
