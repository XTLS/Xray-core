package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	protocolName = "xdrive"
	sessionsDir  = "sessions"
	streamsDir   = "streams"
	uplinkDir    = "c2s"
	downlinkDir  = "s2c"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
	common.Must(internet.RegisterTransportListener(protocolName, Serve))
}

func newSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("failed to generate session id").Base(err)
	}
	return hex.EncodeToString(buf), nil
}

func announceName(session string, at time.Time) string {
	return fmt.Sprintf("%s/%d-%s", sessionsDir, at.UnixNano(), session)
}

func parseAnnounce(entry string) (string, time.Time, bool) {
	session, at, ok := announceParts(entry)
	if !ok || !safeSessionID(session) {
		return "", time.Time{}, false
	}
	return session, at, true
}

// announceParts splits an announcement entry into its session and its time.
// The session is not checked: a caller that turns it into an object name has
// to ask safeSessionID first.
func announceParts(entry string) (string, time.Time, bool) {
	dash := strings.IndexByte(entry, '-')
	if dash <= 0 || dash == len(entry)-1 {
		return "", time.Time{}, false
	}
	nanos, err := strconv.ParseInt(entry[:dash], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return entry[dash+1:], time.Unix(0, nanos), true
}

// A session id reaches object names, so it must not traverse, must not
// collide with another name once a separator is flattened, and must not name
// a reserved file.
func safeSessionID(session string) bool {
	return safeNameChars(session) && !reservedName(session)
}

// A listed name becomes a delete target, so it must be safe to build one
// from.
func safeListedName(name string) bool {
	return safeNameChars(name) && !reservedName(name)
}

func safeNameChars(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return name[0] != '.' && name[len(name)-1] != '.'
}

func reservedName(name string) bool {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(base) == 4 && base[3] >= '1' && base[3] <= '9' {
		return strings.EqualFold(base[:3], "COM") || strings.EqualFold(base[:3], "LPT")
	}
	return false
}

func sessionPrefix(session string) string {
	return streamsDir + "/" + session
}

func uplinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + uplinkDir
}

func downlinkPrefix(session string) string {
	return sessionPrefix(session) + "/" + downlinkDir
}

func streamConfig(streamSettings *internet.MemoryStreamConfig) (*Config, error) {
	if streamSettings == nil {
		return nil, errors.New("missing stream settings")
	}
	config, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || config == nil {
		return nil, errors.New("invalid protocol settings")
	}
	return config, nil
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := streamConfig(streamSettings)
	if err != nil {
		return nil, err
	}

	if streamSettings.Destination == nil && dest.Address != nil {
		front := dest
		front.Network = net.Network_TCP
		patched := *streamSettings
		patched.Destination = &front
		streamSettings = &patched
	}

	storage, err := newStorage(streamSettings)
	if err != nil {
		return nil, err
	}
	storage, err = transferSessionStorage(storage)
	if err != nil {
		return nil, err
	}
	session, err := newSessionID()
	if err != nil {
		storage.Close()
		return nil, err
	}
	p := paramsForStorage(config, storage)
	if slots, ok := storage.(slotStore); ok {
		depth := max(2, p.concurrency)
		ids, err := slots.takeIDs(ctx, 2*(depth+1)+1)
		if err != nil {
			storage.Close()
			return nil, err
		}
		r := lazyRing(session, depth, ids[:len(ids)-1])
		errors.LogInfo(ctx, "opened session ", session, " in ", len(r.Up.Slots), " slots")
		releaseSession, err := holdStorageSession(storage, session)
		if err != nil {
			storage.Close()
			return nil, err
		}
		conn := newSlotConn(context.Background(), slots, r.Up, r.Down, p, nil, func() {
			storage.Close()
			releaseSession()
		})
		writer := conn.writer.(*slotWriter)

		conn.publishWG.Go(func() {
			select {
			case <-conn.ctx.Done():
				return
			case r.First = <-writer.first:
			case <-time.After(25 * time.Millisecond):
			}
			if conn.ctx.Err() != nil {
				return
			}
			announce, _ := json.Marshal(r)
			if len(r.First) != 0 && len(announce) > driveInlineLimit {
				r.First = nil
				announce, _ = json.Marshal(r)
			}
			// An announce failure surfaces as a connection error on the next Write/Read.
			if err := putDriveObject(conn.ctx, slots, ids[len(ids)-1], announceName(session, time.Now()), announce); err != nil && conn.ctx.Err() == nil {
				err = errors.New("failed to announce session ", session).Base(err)
				writer.fail(err)
			}
		})
		return conn, nil
	}

	if err := storage.Put(ctx, announceName(session, time.Now()), nil); err != nil {
		storage.Close()
		return nil, errors.New("failed to announce session ", session).Base(err)
	}
	errors.LogInfo(ctx, "opened session ", session)
	return newConn(context.Background(), storage,
		uplinkPrefix(session), downlinkPrefix(session), p, false, func() {
			storage.Close()
		}), nil
}

type Listener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	addConn internet.ConnHandler
	params

	mu             sync.Mutex
	active         map[string]bool
	handled        map[string]time.Time
	idleSince      map[string]time.Time
	collecting     map[string]bool
	announceWarned map[string]bool
	firstSeen      map[string]time.Time
	lastSeen       map[string]time.Time
	stopping       bool
	cleanupPending map[string]bool
	cleanupQueue   []string
	cleanupRunning int
	loopWG         sync.WaitGroup
	cleanupWG      sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error

	// collectPause spaces the deletion of two collected sessions.
	collectPause time.Duration
}

func Serve(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	config, err := streamConfig(streamSettings)
	if err != nil {
		return nil, err
	}

	storage, err := newStorage(streamSettings)
	if err != nil {
		return nil, err
	}

	listenerCtx, cancel := context.WithCancel(context.Background())
	listener := &Listener{
		ctx:            listenerCtx,
		cancel:         cancel,
		storage:        storage,
		addConn:        addConn,
		params:         paramsForStorage(config, storage),
		active:         make(map[string]bool),
		handled:        make(map[string]time.Time),
		idleSince:      make(map[string]time.Time),
		announceWarned: make(map[string]bool),
		firstSeen:      make(map[string]time.Time),
		lastSeen:       make(map[string]time.Time),
		collectPause:   cleanupSessionPause,
	}

	listener.loopWG.Add(2)
	go func() {
		defer listener.loopWG.Done()
		listener.acceptLoop(ctx)
	}()
	go func() {
		defer listener.loopWG.Done()
		listener.collectLoop(ctx)
	}()

	return listener, nil
}

func (l *Listener) acceptLoop(logCtx context.Context) {
	delay := l.minPollInterval
	active := time.Now()
	for {
		accepted, err := l.acceptPending(logCtx)
		if err != nil && !isAuthError(err) {
			errors.LogWarningInner(logCtx, err, "failed to list sessions")
		}

		switch {
		case accepted:
			active = time.Now()
			delay = l.minPollInterval
		case time.Since(active) < l.eagerWindow:
			delay = l.minPollInterval
		default:
			delay *= 2
			if delay > l.maxPollInterval {
				delay = l.maxPollInterval
			}
		}

		select {
		case <-l.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (l *Listener) acceptPending(logCtx context.Context) (bool, error) {
	sessions, err := l.storage.List(l.ctx, sessionsDir)
	if err != nil {
		return false, err
	}

	accepted := false
	l.mu.Lock()
	now := time.Now()
	for _, listed := range sessions {
		l.lastSeen[listed.Name] = now
		if _, seen := l.firstSeen[listed.Name]; !seen {
			first := listed.created
			if first.IsZero() || first.After(now) {
				first = now
			}
			l.firstSeen[listed.Name] = first
		}
	}
	// Keep first-seen times across brief listing omissions.
	for entry := range l.firstSeen {
		if now.Sub(l.lastSeen[entry]) >= 2*l.sessionTTL {
			delete(l.firstSeen, entry)
			delete(l.lastSeen, entry)
		}
	}
	l.mu.Unlock()

	for _, listed := range sessions {
		entry := listed.Name
		full := sessionsDir + "/" + entry

		session, _, ok := announceParts(entry)
		if !ok {
			// Never construct a deletion path from an unsafe name.
			if safeListedName(entry) {
				l.queueDrop(full)
			}
			continue
		}
		if !safeSessionID(session) {
			continue
		}
		l.mu.Lock()
		expires := l.firstSeen[entry].Add(l.sessionTTL)
		l.mu.Unlock()
		if !time.Now().Before(expires) {
			errors.LogInfo(logCtx, "dropping the stale announcement of session ", session)
			l.queueDrop(full)
			l.queueSessionDrop(session)
			continue
		}
		if !l.claim(session) {
			l.mu.Lock()
			if !l.handled[session].IsZero() {
				l.queueDropLocked(full)
			}
			l.mu.Unlock()
			continue
		}
		admit, cancel := context.WithDeadline(l.ctx, expires)
		announce := listed.Inline
		var conn *Conn
		var loadErr error
		if _, slots := l.storage.(slotStore); slots && len(announce) == 0 {
			announce, loadErr = l.storage.Get(context.WithValue(admit, maxBodyKey{}, int64(driveMaxAnnounce)), full)
		}
		if loadErr == nil && admit.Err() == nil {
			conn = l.newSessionConn(admit, session, announce)
		}
		cancel()
		if conn == nil {
			l.mu.Lock()
			delete(l.active, session)
			delete(l.handled, session)
			warn := loadErr != nil && !l.announceWarned[session]
			if warn {
				l.announceWarned[session] = true
			}
			l.mu.Unlock()
			if warn {
				errors.LogWarningInner(logCtx, loadErr, "failed to read the announcement of session ", session)
			}
			continue
		}
		l.queueDrop(full)
		accepted = true
		l.addConn(conn)
	}
	return accepted, nil
}

const (
	listenerCleanupWorkers = 2
	listenerCleanupQueue   = 128
)

func (l *Listener) queueDrop(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queueDropLocked(name)
}

func (l *Listener) queueSessionDrop(session string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[session] || !l.handled[session].IsZero() || l.collecting[session] {
		return
	}
	if since := l.idleSince[session]; !since.IsZero() && time.Since(since) < l.sessionTTL {
		return
	}
	if l.collecting == nil {
		l.collecting = make(map[string]bool)
	}
	l.collecting[session] = true
	if !l.queueDropLocked(sessionPrefix(session)) {
		delete(l.collecting, session)
	}
}

func (l *Listener) queueDropLocked(name string) bool {
	if l.stopping || l.ctx.Err() != nil || len(l.cleanupQueue) >= listenerCleanupQueue || l.cleanupPending[name] {
		return false
	}
	if l.cleanupPending == nil {
		l.cleanupPending = make(map[string]bool)
	}
	l.cleanupPending[name] = true
	l.cleanupQueue = append(l.cleanupQueue, name)
	if l.cleanupRunning < listenerCleanupWorkers {
		l.cleanupRunning++
		l.cleanupWG.Add(1)
		go l.cleanupWorker()
	}
	return true
}

func (l *Listener) cleanupWorker() {
	defer l.cleanupWG.Done()
	for {
		l.mu.Lock()
		if len(l.cleanupQueue) == 0 {
			l.cleanupRunning--
			l.mu.Unlock()
			return
		}
		name := l.cleanupQueue[0]
		l.cleanupQueue[0] = ""
		l.cleanupQueue = l.cleanupQueue[1:]
		l.mu.Unlock()
		err := l.drop(name)
		l.finishDrop(name, err)
	}
}

func (l *Listener) finishDrop(name string, err error) {
	l.mu.Lock()
	delete(l.cleanupPending, name)
	if strings.HasPrefix(name, streamsDir+"/") {
		session := strings.TrimPrefix(name, streamsDir+"/")
		delete(l.collecting, session)
		if err == nil || err == errSessionInUse || l.idleSince[session].IsZero() {
			l.idleSince[session] = time.Now()
		}
	}
	l.mu.Unlock()
}

func (l *Listener) drop(name string) error {
	ctx := context.WithValue(l.ctx, cleanupKey{}, true)
	var last error
	for attempt := 0; attempt < cleanupMaxRetries && ctx.Err() == nil; attempt++ {
		if err := l.storage.Delete(ctx, name); err == nil {
			return nil
		} else if err == errSessionInUse {
			return err
		} else {
			last = err
			errors.LogDebug(ctx, "failed to drop ", name, ": ", err)
		}
		if attempt+1 < cleanupMaxRetries && sleepContext(ctx, cleanupRetryDelay+jitter(cleanupRetryDelay)) != nil {
			return ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return last
}

func (l *Listener) claim(session string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !safeSessionID(session) {
		return false
	}
	if l.stopping || l.ctx.Err() != nil || l.active[session] || !l.handled[session].IsZero() || l.collecting[session] {
		return false
	}
	if l.active == nil {
		l.active = make(map[string]bool)
	}
	if l.handled == nil {
		l.handled = make(map[string]time.Time)
	}
	l.active[session] = true
	l.handled[session] = time.Now()
	// The session was accepted, so the inactivity it was listed with is over:
	// a claim must not hand the session the age it had before it was taken.
	delete(l.idleSince, session)
	return true
}

// Drive requires a ring announcement; other backends use the WAL.
func (l *Listener) newSessionConn(admit context.Context, session string, announce []byte) *Conn {
	storage, err := acquireSessionStorage(l.storage)
	if err != nil {
		return nil
	}
	releaseSession, err := holdStorageSession(storage, session)
	if err != nil {
		storage.Close()
		return nil
	}
	onClose := func() {
		storage.Close()
		releaseSession()
		l.mu.Lock()
		delete(l.active, session)
		l.mu.Unlock()
	}
	if slots, ok := storage.(slotStore); ok {
		if r, ok := decodeRing(announce); ok {
			r.Up.lazy, r.Down.lazy = r.Lazy, r.Lazy
			r.Up.name, r.Down.name = uplinkPrefix(session), downlinkPrefix(session)
			deadline, _ := admit.Deadline() // acceptPending always supplies the announcement deadline
			if scoped, ok := slots.(interface {
				bindRing(context.Context, ring) error
			}); (ok && scoped.bindRing(admit, r) != nil) || admit.Err() != nil || !time.Now().Before(deadline) {
				onClose()
				return nil
			}
			errors.LogInfo(admit, "accepted session ", session, " in ", len(r.Down.Slots), " slots")
			return newSlotConn(l.ctx, slots, r.Down, r.Up, l.params, r.First, onClose)
		}
		onClose()
		return nil
	}
	errors.LogInfo(admit, "accepted session ", session)
	return newConn(l.ctx, storage, downlinkPrefix(session), uplinkPrefix(session), l.params, true, onClose)
}

func (l *Listener) collectLoop(logCtx context.Context) {
	interval := l.sessionTTL / 2
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-time.After(interval):
		}
		if err := l.collect(); err != nil {
			errors.LogWarningInner(logCtx, err, "failed to collect abandoned sessions")
		}
	}
}

func (l *Listener) collect() error {
	if c, ok := l.storage.(interface{ cooling() bool }); ok && c.cooling() {
		return nil
	}
	ctx := context.WithValue(l.ctx, cleanupKey{}, true)
	ctx = context.WithValue(ctx, namesOnlyKey{}, true)
	sessions, err := l.storage.List(ctx, streamsDir)
	if err != nil {
		return err
	}

	now := time.Now()
	var expired []string

	l.mu.Lock()
	if l.collecting == nil {
		l.collecting = make(map[string]bool)
	}
	present := make(map[string]bool, len(sessions))
	for _, listed := range sessions {
		session := listed.Name
		if !safeSessionID(session) {
			// A listed stream name must never reach an object name.
			continue
		}
		present[session] = true
		if l.active[session] {
			delete(l.idleSince, session)
			continue
		}
		if l.collecting[session] || l.stopping {
			continue
		}
		since, seen := l.idleSince[session]
		if !seen {
			l.idleSince[session] = now
			continue
		}
		if now.Sub(since) >= l.sessionTTL {
			l.collecting[session] = true
			expired = append(expired, session)
		}
	}
	maps.DeleteFunc(l.idleSince, func(id string, _ time.Time) bool { return !present[id] })
	announced := make(map[string]bool)
	for entry, seen := range l.lastSeen {
		if session, _, ok := parseAnnounce(entry); ok && now.Sub(seen) < 2*l.sessionTTL {
			announced[session] = true
		}
	}
	unused := func(id string) bool { return !l.active[id] && !l.collecting[id] && !announced[id] }
	maps.DeleteFunc(l.handled, func(id string, at time.Time) bool { return unused(id) && now.Sub(at) >= 2*l.sessionTTL })
	maps.DeleteFunc(l.announceWarned, func(id string, _ bool) bool { return unused(id) && l.handled[id].IsZero() })
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		for _, session := range expired {
			delete(l.collecting, session)
		}
		l.mu.Unlock()
	}()
	var first error
	for i, session := range expired {
		if i > 0 && l.collectPause > 0 && sleepContext(l.ctx, l.collectPause) != nil {
			return l.ctx.Err()
		}
		if err := l.storage.Delete(ctx, sessionPrefix(session)); err != nil && err != errSessionInUse {
			if first == nil {
				first = err
			}
		} else if err == nil {
			l.mu.Lock()
			delete(l.idleSince, session)
			l.mu.Unlock()
		} else {
			l.mu.Lock()
			l.idleSince[session] = time.Now()
			l.mu.Unlock()
		}
	}
	return first
}

func (l *Listener) Addr() net.Addr {
	return placeholderAddr
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.stopping = true
		l.mu.Unlock()
		if l.cancel != nil {
			l.cancel()
		}
		l.loopWG.Wait()
		l.cleanupWG.Wait()
		l.closeErr = l.storage.Close()
	})
	return l.closeErr
}
