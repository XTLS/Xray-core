package exchange

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
)

// PacketReader returns one datagram and its actual destination or source.
// A zero-length datagram is valid; only a non-nil error ends reading.
// PacketReader and PacketWriter borrow the caller's slice only until return.
type PacketReader interface {
	ReadPacket([]byte) (int, net.Destination, error)
}

type PacketWriter interface {
	WritePacket([]byte, net.Destination) (int, error)
}

// PacketEndpoint owns either the association source or one routed leg. Abort
// must unblock its pending I/O. Only a source has SetWriteDeadline.
type PacketEndpoint struct {
	Reader           PacketReader
	Writer           PacketWriter
	Abort            func()
	SetWriteDeadline func(time.Time) error
	// Nil leaves idle policy with a legacy owner; zero is an immediate timeout.
	IdleTimeout *time.Duration
	CountRead   func(int64)
	CountWrite  func(int64)
}

// RunPacketAssociation keeps one replaceable routed leg. The association owns
// source I/O, while prepare owns the route and preparation of each new leg.
// It requires exclusive ownership of source writes and their deadlines.
func RunPacketAssociation(ctx context.Context, source PacketEndpoint, prepare func(context.Context, net.Destination) (PacketEndpoint, error)) error {
	return runPacketAssociation(ctx, source, prepare, time.Minute)
}

func runPacketAssociation(ctx context.Context, source PacketEndpoint, prepare func(context.Context, net.Destination) (PacketEndpoint, error), responseTimeout time.Duration) error {
	const packetSize = 65535
	if source.Reader == nil || source.Writer == nil || source.SetWriteDeadline == nil || source.Abort == nil {
		return errors.New("packet source requires reader, writer, abort and write deadline")
	}
	if prepare == nil || responseTimeout <= 0 {
		return errors.New("invalid packet association preparation or timeout")
	}
	var sourceOnce sync.Once
	abortSource := func() { sourceOnce.Do(source.Abort) }
	stopAbort := context.AfterFunc(ctx, abortSource)
	defer stopAbort()
	defer abortSource()
	var fatalMu sync.Mutex
	var fatal error
	setFatal := func(err error) {
		if err == nil {
			return
		}
		fatalMu.Lock()
		if fatal == nil {
			fatal = err
		}
		fatalMu.Unlock()
		abortSource()
	}
	getFatal := func() error { fatalMu.Lock(); defer fatalMu.Unlock(); return fatal }

	type packetLeg struct {
		ctx        context.Context
		endpoint   PacketEndpoint
		cancel     context.CancelFunc
		done       chan struct{}
		retired    chan struct{}
		once       sync.Once
		response   *signal.ActivityTimer
		idle       *signal.ActivityTimer
		stopCancel func() bool
		cancelDone chan struct{}
	}
	var current *packetLeg // only the source reader changes this slot
	retire := func(g *packetLeg) {
		g.once.Do(func() {
			g.cancel()
			if g.response != nil {
				g.response.SetTimeout(0)
			}
			if g.idle != nil {
				g.idle.SetTimeout(0)
			}
			// A blocked reply write must finish before the next leg is published.
			if err := source.SetWriteDeadline(time.Now()); err != nil {
				setFatal(err)
			}
			if g.endpoint.Abort != nil {
				g.endpoint.Abort()
			}
			close(g.retired)
		})
	}
	join := func(g *packetLeg, reset bool) error {
		retire(g)
		<-g.retired
		if g.stopCancel != nil && !g.stopCancel() {
			<-g.cancelDone
		}
		<-g.done
		if err := getFatal(); err != nil {
			return err
		}
		if reset {
			if err := source.SetWriteDeadline(time.Time{}); err != nil {
				setFatal(err)
				return err
			}
		}
		return nil
	}
	defer func() {
		if current != nil {
			_ = join(current, false)
		}
	}()
	request := make([]byte, packetSize)
	var reply []byte // association storage; replacement joins the old reader before reuse
	for {
		n, dest, err := source.Reader.ReadPacket(request)
		if failure := getFatal(); failure != nil {
			return failure
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n < 0 || n > len(request) || !dest.IsValid() {
			return errors.New("invalid packet read result")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if current != nil {
			select {
			case <-current.ctx.Done():
				if err := join(current, true); err != nil {
					return err
				}
				current = nil
			default:
			}
		}
		if current == nil {
			legCtx, cancel := context.WithCancel(ctx)
			responseTimer := signal.CancelAfterInactivity(legCtx, cancel, responseTimeout)
			endpoint, prepErr := prepare(legCtx, dest)
			if prepErr != nil || legCtx.Err() != nil || endpoint.Reader == nil || endpoint.Writer == nil || endpoint.Abort == nil {
				responseTimer.SetTimeout(0)
				cancel()
				if endpoint.Abort != nil {
					endpoint.Abort()
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue // preparation consumed this packet; no ambiguous replay
			}
			g := &packetLeg{ctx: legCtx, endpoint: endpoint, cancel: cancel, done: make(chan struct{}), retired: make(chan struct{}), response: responseTimer}
			// Both native activity timers exist before the worker can finish.
			if endpoint.IdleTimeout != nil {
				g.idle = signal.CancelAfterInactivity(legCtx, cancel, *endpoint.IdleTimeout)
			}
			current = g
			g.cancelDone = make(chan struct{})
			g.stopCancel = context.AfterFunc(legCtx, func() { defer close(g.cancelDone); retire(g) })
			if legCtx.Err() != nil {
				retire(g)
				close(g.done) // no reply worker was started
				if err := join(g, true); err != nil {
					return err
				}
				current = nil
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			if reply == nil {
				reply = make([]byte, packetSize)
			}
			go func() {
				defer close(g.done)
				defer retire(g)
				for {
					rn, from, readErr := g.endpoint.Reader.ReadPacket(reply)
					if readErr != nil || rn < 0 || rn > len(reply) || !from.IsValid() {
						return
					}
					if g.endpoint.CountRead != nil {
						g.endpoint.CountRead(int64(rn))
					}
					if g.idle != nil {
						g.idle.Update()
					}
					g.response.Update()
					wn, writeErr := source.Writer.WritePacket(reply[:rn], from)
					if source.CountWrite != nil {
						source.CountWrite(int64(wn))
					}
					if writeErr != nil || wn != rn {
						return
					}
				}
			}()
		}
		if current.idle != nil {
			current.idle.Update()
		}
		if source.CountRead != nil {
			source.CountRead(int64(n))
		}
		wn, writeErr := current.endpoint.Writer.WritePacket(request[:n], dest)
		if current.endpoint.CountWrite != nil {
			current.endpoint.CountWrite(int64(wn))
		}
		if writeErr != nil || wn != n {
			retire(current)
			if err := join(current, true); err != nil {
				return err
			}
			current = nil
			continue // a failed write cannot be replayed safely
		}
		select {
		case <-current.ctx.Done():
			if err := join(current, true); err != nil {
				return err
			}
			current = nil
		default:
		}
	}
}
