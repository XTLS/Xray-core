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
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/transport"
)

// Session has one physical owner. Parent guards phase and registry identity;
// Flow is immutable after publication; its retained route can outlive this ID.
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
	done         chan struct{}
	flow         *inboundFlow
	producer     sync.Mutex
	prev, next   *Session
	listed       bool // carrier owns cold control/retained readiness
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
	gate := c.link.Writer.(*PhysicalWriter)
	for {
		gate.Lock()
		c.RLock()
		live := !c.Closed() && s.phase == outputOpen && c.sessions[s.ID] == s
		c.RUnlock()
		var frames buf.MultiBuffer
		var err error
		if live && (s.first || !raw.IsEmpty() || s.transferType == protocol.TransferTypePacket && len(raw) != 0) {
			frames, err = s.encodeBatch(&raw)
		}
		if err = c.writeAndUnlock(frames, err); err != nil {
			return err
		}
		if !live || c.Closed() {
			return io.ErrClosedPipe
		}
		if len(raw) == 0 || s.transferType == protocol.TransferTypeStream && raw.IsEmpty() {
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

// The initiating producer seals after its DATA attempts. END already belongs
// to the cold owner before foreign cleanup can block.
func (s *Session) CloseWithError(err error) { s.close(err != nil) }

func (s *Session) close(failed bool) { s.terminate(failed, true) }
func (s *Session) abort()            { s.terminate(false, false) }

func (s *Session) cleanup() {
	input, output := s.input, s.output
	for {
		r, ok := input.(*buf.EndpointOverrideReader)
		if !ok {
			break
		}
		input = r.Reader
	}
	for {
		w, ok := output.(*buf.EndpointOverrideWriter)
		if !ok {
			break
		}
		output = w.Writer
	}
	stop := context.AfterFunc(s.parent.ctx, func() {
		common.Interrupt(output)
		common.Interrupt(input)
	})
	defer stop()
	common.Close(output)
	common.Interrupt(input)
}

func (s *Session) terminate(failed, local bool) {
	if s.seal(failed, local) {
		s.cleanup()
	}
}

// The immutable flow precedes carrier ownership. The first client owner
// receives foreign cleanup custody, outside these locks.
func (s *Session) seal(failed, local bool) bool {
	c, x := s.parent, s.flow
	if x != nil {
		x.access.Lock()
		defer x.access.Unlock()
		failed = failed || x.responseErr == io.ErrClosedPipe
	}
	c.Lock()
	first := s.closeLocked(x, failed, local)
	c.Unlock()
	return first && x == nil
}

// closeLocked seals the logical route under flow/carrier ownership. The role's
// producer or carrier sender owns END; the first local failure flag is immutable.
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
	c.unlinkReadyLocked(s)
	if registered && s.phase == outputClosing && !c.Closed() {
		c.queueReadyLocked(s)
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
			} else {
				x.Expire = time.Now().Add(time.Minute)
			}
			x.notify()
		}
	}
	if registered && s.phase == outputAborted {
		delete(c.sessions, s.ID)
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
