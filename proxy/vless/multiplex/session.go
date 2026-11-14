package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/transport"
)

// Session has one physical owner. Parent guards phase and registry identity;
// the retained raw route can outlive this wire ID.
type Session struct {
	input        buf.Reader
	output       buf.Writer
	parent       *carrier
	ID           uint16
	transferType protocol.TransferType
	target       net.Destination
	globalID     [8]byte
	inbound      *session.Inbound
	first        bool
	endFailed    bool // immutable after the first local terminal transition
	phase        byte
	done         *done.Instance
	flow         *inboundFlow
}

const (
	outputStarting = iota
	outputOpen
	outputClosing
	outputAborted
)

// NewSession prepares initiating metadata before any physical admission lock.
func NewSession(ctx context.Context, link *transport.Link) *Session {
	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	s := &Session{
		input: link.Reader, output: link.Writer, target: target,
		transferType: protocol.TransferTypeStream, globalID: xudp.GetGlobalID(ctx), first: true,
	}
	if target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	if session.IsReverseMuxFromContext(ctx) {
		s.inbound = session.InboundFromContext(ctx)
	}
	return s
}

// WriteMultiBuffer requires one serial producer; Close and abort may run concurrently.
func (s *Session) WriteMultiBuffer(raw buf.MultiBuffer) error {
	defer func() { buf.ReleaseMulti(raw) }()
	for {
		frames, err := s.encodeBatch(&raw)
		if err != nil {
			buf.ReleaseMulti(frames)
			buf.ReleaseMulti(raw)
			raw = nil
			return err
		}
		if err := s.parent.appendEntry(s, frames, false); err != nil {
			buf.ReleaseMulti(frames)
			return err
		}
		if len(raw) == 0 {
			return nil
		}
	}
}

func (s *Session) writePayload(data buf.MultiBuffer) error {
	// The parser owns flow replacement; the flow validates server admission.
	x := s.flow
	if x == nil {
		s.parent.RLock()
		live := s.phase == outputOpen || s.phase == outputStarting
		s.parent.RUnlock()
		if !live {
			buf.ReleaseMulti(data)
			return io.ErrClosedPipe
		}
		return s.output.WriteMultiBuffer(data)
	}
	err := x.accept(data, s)
	if err != nil {
		buf.ReleaseMulti(data)
	}
	return err
}

func (s *Session) Close() error                { s.close(true); return nil }
func (s *Session) WaitClosed() <-chan struct{} { return s.done.Wait() }

// CloseWithError finalizes the single producer once after its DATA attempts,
// even if another goroutine already closed logically. Foreign cleanup may wait for
// physical output, so this owner's END admission precedes its cleanup.
func (s *Session) CloseWithError(err error) error {
	if s.seal(err != nil, true) {
		defer s.cleanup()
	}
	c := s.parent
	if !c.client {
		if c.Closed() {
			return io.ErrClosedPipe
		}
		return nil
	}
	c.RLock()
	live := s.phase == outputClosing
	failed := s.endFailed
	c.RUnlock()
	if !live {
		return io.ErrClosedPipe
	}
	frames := endFrame(s.ID, failed)
	if err := c.appendEntry(s, frames, true); err != nil {
		buf.ReleaseMulti(frames)
		return err
	}
	return nil
}

func (s *Session) close(failed bool) { s.terminate(failed, true) }
func (s *Session) abort()            { s.terminate(false, false) }

func (s *Session) cleanup() {
	stop := context.AfterFunc(s.parent.ctx, func() {
		common.Interrupt(s.output)
		common.Interrupt(s.input)
	})
	defer stop()
	common.Close(s.output)
	common.Interrupt(s.input)
}

func (s *Session) terminate(failed, local bool) {
	if s.seal(failed, local) {
		s.cleanup()
	}
}

// Snapshot without retaining the carrier while acquiring route locks. Starting
// retries may replace flow, so recheck under flow -> carrier before close. The
// first client owner receives foreign cleanup custody, outside these locks.
func (s *Session) seal(failed, local bool) bool {
	c := s.parent
	for {
		c.RLock()
		x := s.flow
		c.RUnlock()
		if x != nil {
			x.access.Lock()
		}
		c.Lock()
		same := s.flow == x
		var first bool
		if same {
			if x != nil {
				failed = failed || x.responseErr == io.ErrClosedPipe
			}
			first = s.closeLocked(x, failed, local)
		}
		c.Unlock()
		if x != nil {
			x.access.Unlock()
		}
		if !same {
			continue
		}
		return first && x == nil
	}
}

// closeLocked seals the logical route under flow/carrier ownership. The role's
// producer or binding emitter owns END; the first local failure flag is immutable.
func (s *Session) closeLocked(x *inboundFlow, failed, local bool) (first bool) {
	c := s.parent
	first = s.phase == outputOpen || s.phase == outputStarting
	// A borrowed peer pointer must not rewrite a client's first terminal state.
	if !first && (local || c.client) {
		return false
	}
	registered := c.sessions[s.ID] == s
	if first && s.phase == outputOpen && registered {
		c.active--
	}
	if local && registered && !c.Closed() {
		s.phase = outputClosing
		s.endFailed = failed
	} else {
		s.phase = outputAborted
	}
	if first {
		if s.done != nil {
			s.done.Close()
		}
		if x != nil && x.binding == s {
			x.binding = nil
			if x.GlobalID == [8]byte{} {
				if x.requestErr == nil {
					x.requestErr = io.EOF
				}
				x.responseErr = io.ErrClosedPipe
				x.response = buf.ReleaseMulti(x.response)
			} else {
				x.Expire = time.Now().Add(time.Minute)
			}
			x.notify()
		}
	}
	if registered && (s.phase == outputAborted || c.client && first) {
		delete(c.sessions, s.ID)
	}
	if first && c.client {
		c.tx.Lock()
		c.ready.Broadcast()
		c.tx.Unlock()
	}
	return
}

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*inboundFlow
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*inboundFlow)
	go func() {
		for {
			time.Sleep(time.Minute)
			now := time.Now()
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
	}()
}
