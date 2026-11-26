package multiplex

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/transport"
)

// Session has one physical owner. Parent guards phase and registry identity;
// Flow is immutable after publication; its retained route can outlive this ID.
type Session struct {
	input     buf.Reader
	output    buf.Writer
	parent    *carrier
	ID        uint16
	target    net.Destination
	globalID  [8]byte
	inbound   *session.Inbound
	first     bool
	endFailed bool // immutable after the first local terminal transition
	phase     byte
	done      chan struct{}
	flow      *inboundFlow
	producer  sync.Mutex

	writingResponse atomic.Bool
}

const (
	outputStarting = iota
	outputOpen
	outputDone
)

// NewSession prepares initiating metadata before any physical admission lock.
func NewSession(ctx context.Context, link *transport.Link) *Session {
	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	s := &Session{
		input: link.Reader, output: link.Writer, target: target,
		globalID: xudp.GetGlobalID(ctx), first: true,
	}
	if session.IsReverseMuxFromContext(ctx) {
		s.inbound = session.InboundFromContext(ctx)
	}
	return s
}

// Initiating input is serial; native server callbacks are serialized per offer.
// Existing producers own DATA through direct physical admission.
func (s *Session) WriteMultiBuffer(raw buf.MultiBuffer) error {
	c := s.parent
	c.RLock()
	live := !c.Closed() && s.phase == outputOpen && c.sessions[s.ID] == s
	c.RUnlock()
	if !live {
		buf.ReleaseMulti(raw)
		return io.ErrClosedPipe
	}
	if !c.client {
		s.producer.Lock()
		defer s.producer.Unlock()
	}
	defer func() { buf.ReleaseMulti(raw) }()
	for {
		c.writeMutex.Lock()
		c.RLock()
		live := !c.Closed() && s.phase == outputOpen && c.sessions[s.ID] == s
		c.RUnlock()
		var frames buf.MultiBuffer
		var err error
		if live {
			frames, err = s.encodeBatch(&raw)
		}
		if err = c.writeAndUnlock(frames, err); err != nil {
			return err
		}
		if !live || c.Closed() {
			return io.ErrClosedPipe
		}
		if len(raw) == 0 {
			return nil
		}
	}
}

func (s *Session) writePayload(data buf.MultiBuffer) error {
	// The flow validates server admission for this immutable binding.
	x := s.flow
	if x == nil {
		s.parent.RLock()
		live := s.phase == outputOpen || s.phase == outputStarting
		if live {
			s.writingResponse.Store(true)
		}
		s.parent.RUnlock()
		if !live {
			buf.ReleaseMulti(data)
			return io.ErrClosedPipe
		}
		defer s.writingResponse.Store(false)
		return s.output.WriteMultiBuffer(data)
	}
	err := x.accept(data, s)
	if err != nil {
		buf.ReleaseMulti(data)
	}
	return err
}

func (s *Session) Close() error {
	if s.parent.client {
		s.close(true)
		return nil
	}
	s.producer.Lock()
	defer s.producer.Unlock()
	s.close(false)
	return nil
}
func (s *Session) Interrupt()                  { s.close(true) }
func (s *Session) WaitClosed() <-chan struct{} { return s.done }

func (s *Session) CloseWithError(err error) { s.close(err != nil) }

func (s *Session) close(failed bool) { s.seal(failed, true) }
func (s *Session) abort()            { s.seal(false, false) }

func (s *Session) seal(failed, local bool) {
	c, x := s.parent, s.flow
	if x != nil {
		x.access.Lock()
		defer x.access.Unlock()
	}
	c.Lock()
	s.closeLocked(x, failed, local)
	c.Unlock()
}

// closeLocked seals the logical route under flow/carrier ownership. The role's
// producer or carrier sender owns END; the first local failure flag is immutable.
func (s *Session) closeLocked(x *inboundFlow, failed, local bool) {
	c := s.parent
	first := s.phase != outputDone
	// A borrowed peer pointer must not rewrite a client's first terminal state.
	if !first && (local || c.client) {
		return
	}
	registered := c.sessions[s.ID] == s
	if s.phase == outputOpen && registered {
		c.active--
	}
	s.phase = outputDone
	// A terminal row retained in the registry owns a pending END.
	if registered && local && !c.Closed() {
		s.endFailed = failed
		c.queueReadyLocked(s)
	} else if registered {
		delete(c.ready, s.ID)
		delete(c.sessions, s.ID)
	}
	if first {
		if s.done != nil {
			close(s.done)
		}
		if x != nil && x.binding == s {
			x.binding = nil
			if x.GlobalID == [8]byte{} {
				if x.requestErr == nil {
					x.requestErr = io.EOF
				}
				x.responseErr = io.ErrClosedPipe
				x.response = buf.ReleaseMulti(x.response)
				x.responseWake.Broadcast()
			} else {
				x.Expire = time.Now().Add(time.Minute)
			}
			x.requestWake.Broadcast()
		}
	}
}

var XUDPManager = struct {
	sync.Mutex
	Map map[[8]byte]*inboundFlow
}{Map: make(map[[8]byte]*inboundFlow)}

func init() { time.AfterFunc(time.Minute, scheduleXUDPSweep) }

func scheduleXUDPSweep() {
	sweepXUDP(time.Now())
	time.AfterFunc(time.Minute, scheduleXUDPSweep)
}

func sweepXUDP(now time.Time) {
	var expired []*inboundFlow
	XUDPManager.Lock()
	for id, x := range XUDPManager.Map {
		x.access.Lock()
		if x.binding == nil && !x.Expire.IsZero() && now.After(x.Expire) {
			expired = append(expired, x)
			delete(XUDPManager.Map, id)
		}
		x.access.Unlock()
	}
	XUDPManager.Unlock()
	for _, x := range expired {
		errors.LogDebug(context.Background(), "XUDP del ", x.GlobalID)
		x.expire()
	}
}
