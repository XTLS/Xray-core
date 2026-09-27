package exchange

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type lifecyclePacket struct {
	data []byte
	dest net.Destination
}

type lifecycleSource struct {
	requests     chan lifecyclePacket
	done         chan struct{}
	once         sync.Once
	writeStarted chan struct{}
	unblock      chan struct{}
	unblockOnce  sync.Once
	writes       atomic.Int32
	expires      atomic.Int32
	resets       atomic.Int32
	failDeadline bool
	failReset    bool
}

func newLifecycleSource() *lifecycleSource {
	return &lifecycleSource{requests: make(chan lifecyclePacket), done: make(chan struct{}), writeStarted: make(chan struct{}), unblock: make(chan struct{})}
}

func (s *lifecycleSource) ReadPacket(p []byte) (int, net.Destination, error) {
	select {
	case packet := <-s.requests:
		return copy(p, packet.data), packet.dest, nil
	case <-s.done:
		return 0, net.Destination{}, io.EOF
	}
}

func (s *lifecycleSource) WritePacket(p []byte, _ net.Destination) (int, error) {
	if s.writes.Add(1) == 1 {
		close(s.writeStarted)
		<-s.unblock
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (s *lifecycleSource) SetWriteDeadline(t time.Time) error {
	if s.failDeadline {
		return errors.New("deadline unavailable")
	}
	if t.IsZero() && s.failReset {
		return errors.New("deadline reset unavailable")
	}
	if t.IsZero() {
		s.resets.Add(1)
	} else {
		s.expires.Add(1)
		s.unblockOnce.Do(func() { close(s.unblock) })
	}
	return nil
}

func (s *lifecycleSource) Abort() {
	s.once.Do(func() { close(s.done); s.unblockOnce.Do(func() { close(s.unblock) }) })
}

type lifecycleLeg struct {
	replies    chan lifecyclePacket
	done       chan struct{}
	once       sync.Once
	writes     atomic.Int32
	writeError bool
}

func newLifecycleLeg() *lifecycleLeg {
	return &lifecycleLeg{replies: make(chan lifecyclePacket, 1), done: make(chan struct{})}
}
func (l *lifecycleLeg) ReadPacket(p []byte) (int, net.Destination, error) {
	select {
	case packet := <-l.replies:
		return copy(p, packet.data), packet.dest, nil
	case <-l.done:
		return 0, net.Destination{}, io.EOF
	}
}
func (l *lifecycleLeg) WritePacket(p []byte, dest net.Destination) (int, error) {
	l.writes.Add(1)
	if l.writeError {
		return 0, io.ErrClosedPipe
	}
	select {
	case l.replies <- lifecyclePacket{data: append([]byte(nil), p...), dest: dest}:
	case <-l.done:
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func (l *lifecycleLeg) Abort() { l.once.Do(func() { close(l.done) }) }

func awaitPacketCondition(t *testing.T, label string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !check() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !check() {
		t.Fatal(label)
	}
}

func TestPacketRetireJoinsBlockedReplyBeforeDeadlineReset(t *testing.T) {
	source := newLifecycleSource()
	first, second := newLifecycleLeg(), newLifecycleLeg()
	a, b := net.UDPDestination(net.LocalHostIP, 10001), net.UDPDestination(net.LocalHostIP, 10002)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var routes atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(_ context.Context, dest net.Destination) (PacketEndpoint, error) {
			routes.Add(1)
			if dest == a {
				return PacketEndpoint{Reader: first, Writer: first, Abort: first.Abort, IdleTimeout: packetIdle(25 * time.Millisecond)}, nil
			}
			if dest == b {
				return PacketEndpoint{Reader: second, Writer: second, Abort: second.Abort, IdleTimeout: packetIdle(time.Second)}, nil
			}
			return PacketEndpoint{}, errors.New("unexpected route")
		}, time.Second)
	}()
	source.requests <- lifecyclePacket{data: []byte{1}, dest: a}
	select {
	case <-source.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("reply did not block")
	}
	awaitPacketCondition(t, "first leg did not expire write deadline", func() bool { return source.expires.Load() > 0 })
	source.requests <- lifecyclePacket{data: []byte{2}, dest: b}
	awaitPacketCondition(t, "second route not prepared", func() bool { return routes.Load() == 2 })
	awaitPacketCondition(t, "second reply not written", func() bool { return source.writes.Load() >= 2 })
	if source.resets.Load() != 1 {
		t.Fatalf("deadline resets=%d", source.resets.Load())
	}
	select {
	case <-source.done:
		t.Fatal("source closed on leg expiry")
	default:
	}
	first.Abort() // late callback from an old leg cannot affect this source
	if source.expires.Load() != 1 {
		t.Fatal("old leg poisoned new deadline")
	}
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("association did not join")
	}
}

func TestPacketResponseTimerIgnoresRequestsAndIdleCanBeShorter(t *testing.T) {
	for _, tc := range []struct {
		name           string
		response, idle time.Duration
	}{
		{"response", 35 * time.Millisecond, time.Second},
		{"idle", time.Second, 35 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := newLifecycleSource()
			leg := newLifecycleLeg()
			// No replies: request traffic must not refresh response-only expiry.
			leg.writeError = true
			// A writer failure retires immediately, so use a quiet writer below.
			writer := packetDiscardWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
					return PacketEndpoint{Reader: leg, Writer: writer, Abort: leg.Abort, IdleTimeout: packetIdle(tc.idle)}, nil
				}, tc.response)
			}()
			dest := net.UDPDestination(net.LocalHostIP, 10001)
			for i := 0; i < 3; i++ {
				source.requests <- lifecyclePacket{data: []byte{1}, dest: dest}
				time.Sleep(8 * time.Millisecond)
			}
			awaitPacketCondition(t, "timer did not retire leg", func() bool { return source.expires.Load() > 0 })
			cancel()
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("association did not stop")
			}
		})
	}
}

type packetDiscardWriter struct{}

func (packetDiscardWriter) WritePacket(p []byte, _ net.Destination) (int, error) { return len(p), nil }

func TestPacketSourceDeadlineCapabilityAndFailure(t *testing.T) {
	source := newLifecycleSource()
	endpoint := PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort}
	if err := RunPacketAssociation(context.Background(), endpoint, nil); err == nil {
		t.Fatal("missing deadline accepted")
	}
	source.failDeadline = true
	endpoint.SetWriteDeadline = source.SetWriteDeadline
	leg := newLifecycleLeg()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(ctx, endpoint, func(context.Context, net.Destination) (PacketEndpoint, error) {
			return PacketEndpoint{Reader: leg, Writer: packetDiscardWriter{}, Abort: leg.Abort, IdleTimeout: packetIdle(15 * time.Millisecond)}, nil
		}, time.Second)
	}()
	source.requests <- lifecyclePacket{data: []byte{1}, dest: net.UDPDestination(net.LocalHostIP, 1)}
	select {
	case err := <-result:
		if err == nil || err.Error() != "deadline unavailable" {
			t.Fatalf("result=%v", err)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("deadline failure did not abort")
	}
	cancel()
}

func TestPacketDeadlineResetFailureAbortsAssociation(t *testing.T) {
	source := newLifecycleSource()
	source.failReset = true
	leg := newLifecycleLeg()
	leg.writeError = true
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(context.Background(), PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			return PacketEndpoint{Reader: leg, Writer: leg, Abort: leg.Abort}, nil
		}, time.Second)
	}()
	source.requests <- lifecyclePacket{data: []byte{1}, dest: net.UDPDestination(net.LocalHostIP, 1)}
	select {
	case err := <-result:
		if err == nil || err.Error() != "deadline reset unavailable" {
			t.Fatalf("result=%v", err)
		}
	case <-time.After(time.Second):
		source.Abort()
		t.Fatal("failed reset did not abort association")
	}
	select {
	case <-source.done:
	default:
		t.Fatal("source remained open after failed reset")
	}
}

func TestPacketFailedLegWriteIsNotReplayed(t *testing.T) {
	source := newLifecycleSource()
	first, second := newLifecycleLeg(), newLifecycleLeg()
	first.writeError = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var routes atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			if routes.Add(1) == 1 {
				return PacketEndpoint{Reader: first, Writer: first, Abort: first.Abort}, nil
			}
			return PacketEndpoint{Reader: second, Writer: second, Abort: second.Abort}, nil
		}, time.Second)
	}()
	dest := net.UDPDestination(net.LocalHostIP, 10001)
	source.requests <- lifecyclePacket{data: []byte{1}, dest: dest}
	awaitPacketCondition(t, "failed leg not retired", func() bool { return source.resets.Load() == 1 })
	if first.writes.Load() != 1 || routes.Load() != 1 {
		t.Fatal("ambiguous packet replayed")
	}
	source.requests <- lifecyclePacket{data: []byte{2}, dest: dest}
	awaitPacketCondition(t, "replacement not prepared", func() bool { return routes.Load() == 2 })
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
}

func TestPacketFailedPreparationDoesNotCountTransfer(t *testing.T) {
	source := newLifecycleSource()
	leg := newLifecycleLeg()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts, counted atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline, CountRead: func(int64) { counted.Add(1) }}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			if attempts.Add(1) == 1 {
				return PacketEndpoint{}, errors.New("route unavailable")
			}
			return PacketEndpoint{Reader: leg, Writer: packetDiscardWriter{}, Abort: leg.Abort}, nil
		}, time.Second)
	}()
	dest := net.UDPDestination(net.LocalHostIP, 10001)
	source.requests <- lifecyclePacket{data: []byte{1}, dest: dest}
	awaitPacketCondition(t, "failed preparation was not attempted", func() bool { return attempts.Load() == 1 })
	if counted.Load() != 0 {
		t.Fatal("failed preparation counted user transfer")
	}
	source.requests <- lifecyclePacket{data: []byte{2}, dest: dest}
	awaitPacketCondition(t, "successful preparation did not consume packet", func() bool { return counted.Load() == 1 })
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
}

func TestPacketPreparationTimeoutClosesLateLegAndKeepsSource(t *testing.T) {
	source := newLifecycleSource()
	late, next := newLifecycleLeg(), newLifecycleLeg()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(prepCtx context.Context, _ net.Destination) (PacketEndpoint, error) {
			if attempts.Add(1) == 1 {
				<-prepCtx.Done()
				return PacketEndpoint{Reader: late, Writer: packetDiscardWriter{}, Abort: late.Abort}, nil
			}
			return PacketEndpoint{Reader: next, Writer: packetDiscardWriter{}, Abort: next.Abort}, nil
		}, 25*time.Millisecond)
	}()
	dest := net.UDPDestination(net.LocalHostIP, 10001)
	source.requests <- lifecyclePacket{data: []byte{1}, dest: dest}
	awaitPacketCondition(t, "late prepared leg was not closed", func() bool {
		select {
		case <-late.done:
			return true
		default:
			return false
		}
	})
	select {
	case <-source.done:
		t.Fatal("preparation timeout closed association")
	default:
	}
	source.requests <- lifecyclePacket{data: []byte{2}, dest: dest}
	awaitPacketCondition(t, "source did not prepare replacement", func() bool { return attempts.Load() == 2 })
	cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
}

func packetIdle(d time.Duration) *time.Duration { return &d }

func TestPacketZeroIdleIsImmediateNotDisabled(t *testing.T) {
	source := newLifecycleSource()
	leg := newLifecycleLeg()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			return PacketEndpoint{Reader: leg, Writer: leg, Abort: leg.Abort, IdleTimeout: packetIdle(0)}, nil
		}, time.Hour)
	}()
	source.requests <- lifecyclePacket{data: []byte{1}, dest: net.UDPDestination(net.LocalHostIP, 1)}
	select {
	case <-leg.done:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("zero idle was disabled")
	}
	select {
	case <-source.done:
		t.Fatal("leg expiry closed association")
	default:
	}
	if leg.writes.Load() != 0 {
		t.Fatal("expired leg accepted a packet")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association did not join")
	}
}

func TestPacketMissingLegAbortDoesNotStartUninterruptibleReader(t *testing.T) {
	source := &scriptedPacketSource{packets: []net.Destination{net.UDPDestination(net.LocalHostIP, 1)}, done: make(chan struct{})}
	leg := &scriptedPacketLeg{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			return PacketEndpoint{Reader: leg, Writer: leg}, nil
		})
	}()
	awaitPacketCondition(t, "did not return to association reading", func() bool { return source.reads.Load() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		leg.Abort()
		<-done
		t.Fatal("uninterruptible leg was admitted")
	}
	if leg.exited.Load() {
		t.Fatal("malformed leg reader was invoked")
	}
	leg.Abort()
}
