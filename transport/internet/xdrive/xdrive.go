package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

const protocolName = "xdrive"

type names struct {
	sessionsDir, streamsDir, uplinkDir, downlinkDir string
	segSuffix, endSuffix, errSuffix                 string
}

func namesFromConfig(c *Config) names {
	n := names{
		sessionsDir: "sessions",
		streamsDir:  "streams",
		uplinkDir:   "c2s",
		downlinkDir: "s2c",
		segSuffix:   ".seg",
		endSuffix:   ".end",
		errSuffix:   ".err",
	}
	cfg := c.GetNaming()
	if cfg == nil {
		return n
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&n.sessionsDir, cfg.SessionsDir)
	set(&n.streamsDir, cfg.StreamsDir)
	set(&n.uplinkDir, cfg.UplinkDir)
	set(&n.downlinkDir, cfg.DownlinkDir)
	set(&n.segSuffix, cfg.SegSuffix)
	set(&n.endSuffix, cfg.EndSuffix)
	set(&n.errSuffix, cfg.ErrSuffix)
	return n
}

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

func (n names) announceName(session string, at time.Time) string {
	return fmt.Sprintf("%s/%d-%s", n.sessionsDir, at.UnixNano(), session)
}

func parseAnnounce(entry string) (string, time.Time, bool) {
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

func (n names) sessionPrefix(session string) string {
	return n.streamsDir + "/" + session
}

func (n names) uplinkPrefix(session string) string {
	return n.sessionPrefix(session) + "/" + n.uplinkDir
}

func (n names) downlinkPrefix(session string) string {
	return n.sessionPrefix(session) + "/" + n.downlinkDir
}

func streamConfig(streamSettings *internet.MemoryStreamConfig) (*Config, error) {
	config, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || config == nil {
		return nil, errors.New("invalid protocol settings")
	}
	return config, nil
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	config, err := streamConfig(streamSettings)
	if err != nil {
		return nil, err
	}

	storage, err := newStorage(streamSettings)
	if err != nil {
		return nil, err
	}

	session, err := newSessionID()
	if err != nil {
		storage.Close()
		return nil, err
	}

	p := paramsFromConfig(config)
	if err := storage.Put(ctx, p.announceName(session, time.Now()), nil); err != nil {
		storage.Close()
		return nil, errors.New("failed to announce session ", session).Base(err)
	}

	errors.LogInfo(ctx, "opened session ", session)

	return newConn(context.Background(), storage,
		p.uplinkPrefix(session), p.downlinkPrefix(session), p, func() {
			storage.Close()
		}), nil
}

type Listener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	addConn internet.ConnHandler
	params

	mu        sync.Mutex
	active    map[string]bool
	handled   map[string]time.Time
	idleSince map[string]time.Time
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
		ctx:       listenerCtx,
		cancel:    cancel,
		storage:   storage,
		addConn:   addConn,
		params:    paramsFromConfig(config),
		active:    make(map[string]bool),
		handled:   make(map[string]time.Time),
		idleSince: make(map[string]time.Time),
	}

	go listener.acceptLoop(ctx)
	go listener.collectLoop(ctx)

	return listener, nil
}

func (l *Listener) acceptLoop(logCtx context.Context) {
	delay := l.minPollInterval
	active := time.Now()
	for {
		accepted, err := l.acceptPending(logCtx)
		if err != nil {
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
	sessions, err := l.storage.List(l.ctx, l.sessionsDir)
	if err != nil {
		return false, err
	}

	accepted := false
	for _, listed := range sessions {
		entry := listed.Name
		full := l.sessionsDir + "/" + entry

		session, at, ok := parseAnnounce(entry)
		if !ok {
			go l.drop(full)
			continue
		}
		if time.Since(at) > l.sessionTTL {
			errors.LogInfo(logCtx, "dropping the stale announcement of session ", session)
			go l.drop(full)
			go l.drop(l.sessionPrefix(session))
			continue
		}
		if !l.claim(session) {
			continue
		}
		go l.drop(full)
		errors.LogInfo(logCtx, "accepted session ", session)
		accepted = true
		l.addConn(l.newSessionConn(session))
	}
	return accepted, nil
}

func (l *Listener) drop(name string) {
	l.storage.Delete(l.ctx, name)
}

func (l *Listener) claim(session string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[session] || !l.handled[session].IsZero() {
		return false
	}
	l.active[session] = true
	l.handled[session] = time.Now()
	return true
}

func (l *Listener) newSessionConn(session string) *Conn {
	return newConn(l.ctx, l.storage,
		l.downlinkPrefix(session), l.uplinkPrefix(session), l.params, func() {
			l.mu.Lock()
			delete(l.active, session)
			l.mu.Unlock()
		})
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
	sessions, err := l.storage.List(l.ctx, l.streamsDir)
	if err != nil {
		return err
	}

	now := time.Now()
	var expired []string

	l.mu.Lock()
	present := make(map[string]bool, len(sessions))
	for _, listed := range sessions {
		session := listed.Name
		present[session] = true
		if l.active[session] {
			delete(l.idleSince, session)
			continue
		}
		since, seen := l.idleSince[session]
		if !seen {
			l.idleSince[session] = now
			continue
		}
		if now.Sub(since) >= l.sessionTTL {
			expired = append(expired, session)
			delete(l.idleSince, session)
		}
	}
	for session := range l.idleSince {
		if !present[session] {
			delete(l.idleSince, session)
		}
	}
	for session, at := range l.handled {
		if !l.active[session] && now.Sub(at) >= l.sessionTTL {
			delete(l.handled, session)
		}
	}
	l.mu.Unlock()

	for _, session := range expired {
		if err := l.storage.Delete(l.ctx, l.sessionPrefix(session)); err != nil {
			return err
		}
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return placeholderAddr
}

func (l *Listener) Close() error {
	l.cancel()
	return l.storage.Close()
}
