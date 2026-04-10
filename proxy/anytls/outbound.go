package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	sessionctx "github.com/xtls/xray-core/common/session"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 60 * time.Second
	defaultMinIdleSession           = 0
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager

	idleSessionCheckInterval time.Duration
	idleSessionTimeout       time.Duration
	minIdleSession           int

	defaultPaddingScheme *paddingScheme
	authPadding          uint16
	authHash             [32]byte

	poolMu       sync.Mutex
	idleSessions []uint64
	sessionsMu   sync.Mutex
	sessions     map[uint64]*session
	sessionSeq   atomic.Uint64
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config == nil || config.Server == nil {
		return nil, errors.New("anytls: no server specified")
	}

	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("anytls: no user specified")
	}
	account, ok := server.User.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("anytls: invalid account type")
	}

	v := core.MustFromContext(ctx)
	client := &Client{
		server:                   server,
		policyManager:            v.GetFeature(policy.ManagerType()).(policy.Manager),
		idleSessionCheckInterval: defaultIdleSessionCheckInterval,
		idleSessionTimeout:       defaultIdleSessionTimeout,
		minIdleSession:           defaultMinIdleSession,
		defaultPaddingScheme:     getDefaultPaddingScheme(),
		authHash:                 sha256.Sum256([]byte(account.Password)),
		sessions:                 make(map[uint64]*session),
	}
	client.authPadding = getPadding0Size(client.defaultPaddingScheme)
	if value := config.GetIdleSessionCheckInterval(); value > 0 {
		client.idleSessionCheckInterval = time.Duration(value) * time.Second
	}
	if value := config.GetIdleSessionTimeout(); value > 0 {
		client.idleSessionTimeout = time.Duration(value) * time.Second
	}
	client.minIdleSession = int(config.GetMinIdleSession())
	go client.cleanupIdleSessions()
	return client, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := sessionctx.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	server := c.server
	dest := server.Destination

	var sess *session
	c.poolMu.Lock()
	c.sessionsMu.Lock()
	for len(c.idleSessions) > 0 {
		last := len(c.idleSessions) - 1
		seq := c.idleSessions[last]
		c.idleSessions = c.idleSessions[:last]
		sess = c.sessions[seq]
		if sess == nil {
			continue
		}
		sess.inIdlePool.Store(false)
		if sess.isClosed() {
			sess = nil
			continue
		}
		break
	}
	c.sessionsMu.Unlock()
	c.poolMu.Unlock()

	if sess == nil {
		seq := c.sessionSeq.Add(1)
		var conn stat.Connection
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			rawConn, err := dialer.Dial(ctx, dest)
			if err != nil {
				return err
			}
			conn = rawConn
			return nil
		})
		if err != nil {
			return errors.New("anytls: failed to establish connection").AtWarning().Base(err)
		}

		var auth [34]byte
		copy(auth[:32], c.authHash[:])
		binary.BigEndian.PutUint16(auth[32:34], c.authPadding)
		if _, err := conn.Write(auth[:]); err != nil {
			conn.Close()
			return errors.New("anytls: write auth failed").Base(err)
		}
		if c.authPadding > 0 {
			pad := buf.New()
			pad.Extend(int32(c.authPadding))
			_, err := conn.Write(pad.Bytes())
			pad.Release()
			if err != nil {
				conn.Close()
				return errors.New("anytls: write padding failed").Base(err)
			}
		}

		sess = &session{
			client:        c,
			isClient:      true,
			conn:          conn,
			br:            &buf.BufferedReader{Reader: buf.NewReader(conn)},
			bw:            buf.NewBufferedWriter(buf.NewWriter(conn)),
			paddingScheme: c.defaultPaddingScheme,
			streams:       make(map[uint32]*stream),
			synAckCh:      make(map[uint32]chan error),
			errCh:         make(chan error, 1),
			seq:           seq,
		}
		sess.fw = newFrameWriter(sess.bw)
		sess.nextSID.Store(1)
		sess.pktCounter.Store(1)
		sess.peerVersion = 1
		sess.dieHook = func() {
			c.sessionsMu.Lock()
			delete(c.sessions, sess.seq)
			c.sessionsMu.Unlock()
		}
		c.sessionsMu.Lock()
		c.sessions[seq] = sess
		c.sessionsMu.Unlock()
		errors.LogDebug(ctx, "anytls: new session created, seq=", seq)

		go func() {
			if err := sess.readLoop(ctx); err != nil && !sess.isClosed() {
				sess.close(err)
			}
		}()
	}

	stream, err := sess.openStream(ctx, destination, link)
	if err != nil {
		sess.close(err)
		return errors.New("anytls: failed to open stream").Base(err)
	}
	stream.dieHook = func() {
		if sess.isClosed() || sess.activeStreams.Load() != 0 {
			return
		}
		c.markSessionIdle(sess)
	}
	go stream.pumpUplink(sess)

	select {
	case <-stream.done:
		return stream.result()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) markSessionIdle(sess *session) {
	if sess == nil || sess.isClosed() {
		return
	}
	if !sess.inIdlePool.CompareAndSwap(false, true) {
		return
	}
	sess.idleSinceNano.Store(time.Now().UnixNano())

	c.poolMu.Lock()
	c.idleSessions = append(c.idleSessions, sess.seq)
	c.poolMu.Unlock()
}

func (c *Client) cleanupIdleSessions() {
	ticker := time.NewTicker(c.idleSessionCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		var toClose []*session

		c.poolMu.Lock()
		if len(c.idleSessions) == 0 {
			c.poolMu.Unlock()
			continue
		}

		c.sessionsMu.Lock()
		validCount := 0
		for _, seq := range c.idleSessions {
			sess := c.sessions[seq]
			if sess == nil || sess.isClosed() || !sess.inIdlePool.Load() {
				continue
			}
			c.idleSessions[validCount] = seq
			validCount++
		}
		c.idleSessions = c.idleSessions[:validCount]

		keepFrom := validCount - c.minIdleSession
		if keepFrom < 0 {
			keepFrom = 0
		}

		keptCount := 0
		for idx, seq := range c.idleSessions {
			sess := c.sessions[seq]
			if sess == nil {
				continue
			}
			if idx >= keepFrom {
				c.idleSessions[keptCount] = seq
				keptCount++
				continue
			}
			idleSinceNano := sess.idleSinceNano.Load()
			if idleSinceNano == 0 || now.Sub(time.Unix(0, idleSinceNano)) <= c.idleSessionTimeout {
				c.idleSessions[keptCount] = seq
				keptCount++
				continue
			}
			sess.inIdlePool.Store(false)
			toClose = append(toClose, sess)
		}
		c.sessionsMu.Unlock()
		c.idleSessions = c.idleSessions[:keptCount]
		c.poolMu.Unlock()

		for _, sess := range toClose {
			sess.close(nil)
		}
	}
}
