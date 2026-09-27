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

type scriptedPacketSource struct {
	mu        sync.Mutex
	packets   []net.Destination
	next      chan net.Destination
	written   []net.Destination
	done      chan struct{}
	once      sync.Once
	reads     atomic.Int32
	deadlines atomic.Int32
}

func TestPacketLatePreparationClosesItsResult(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		source := &scriptedPacketSource{packets: []net.Destination{net.UDPDestination(net.LocalHostIP, 1)}, done: make(chan struct{})}
		leg := &scriptedPacketLeg{done: make(chan struct{})}
		err := RunPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			cancel()
			<-source.done
			return PacketEndpoint{Reader: leg, Writer: leg, Abort: leg.Abort}, nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		select {
		case <-leg.done:
		default:
			t.Fatal("late result escaped abort")
		}
	}
}

func TestE1PacketLegRetiresAndAssociationRoutesAgain(t *testing.T) {
	a := net.UDPDestination(net.LocalHostIP, 1)
	b := net.UDPDestination(net.LocalHostIP, 2)
	source := &scriptedPacketSource{packets: []net.Destination{a}, next: make(chan net.Destination), done: make(chan struct{})}
	first := &scriptedPacketLeg{done: make(chan struct{})}
	second := &scriptedPacketLeg{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var count atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- RunPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(_ context.Context, dest net.Destination) (PacketEndpoint, error) {
			if dest == a && count.Add(1) == 1 {
				return PacketEndpoint{Reader: first, Writer: first, Abort: first.Abort}, nil
			}
			if dest == b && count.Add(1) == 2 {
				return PacketEndpoint{Reader: second, Writer: second, Abort: second.Abort}, nil
			}
			return PacketEndpoint{}, errors.New("unexpected route")
		})
	}()
	deadline := time.Now().Add(time.Second)
	for source.reads.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	first.Abort()
	deadline = time.Now().Add(time.Second)
	for source.deadlines.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if source.deadlines.Load() == 0 {
		t.Fatal("first leg did not retire")
	}
	source.next <- b
	deadline = time.Now().Add(time.Second)
	for count.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 2 {
		t.Fatal("replacement leg not prepared")
	}
	select {
	case <-source.done:
		t.Fatal("leg retirement closed association")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association did not join")
	}
}

func (s *scriptedPacketSource) ReadPacket(p []byte) (int, net.Destination, error) {
	s.reads.Add(1)
	s.mu.Lock()
	if len(s.packets) > 0 {
		dest := s.packets[0]
		s.packets = s.packets[1:]
		s.mu.Unlock()
		return copy(p, []byte{1}), dest, nil
	}
	s.mu.Unlock()
	if s.next != nil {
		select {
		case dest := <-s.next:
			return copy(p, []byte{1}), dest, nil
		case <-s.done:
		}
	} else {
		<-s.done
	}
	return 0, net.Destination{}, io.EOF
}

type blockedPacketWriter struct {
	started chan struct{}
	done    <-chan struct{}
	once    sync.Once
}

func (w *blockedPacketWriter) WritePacket([]byte, net.Destination) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.done
	return 0, io.ErrClosedPipe
}

func TestPacketAssociationCancelUnblocksPressure(t *testing.T) {
	dest := net.UDPDestination(net.LocalHostIP, 10001)
	source := &scriptedPacketSource{packets: []net.Destination{dest}, done: make(chan struct{})}
	leg := &scriptedPacketLeg{done: make(chan struct{})}
	writer := &blockedPacketWriter{started: make(chan struct{}), done: leg.done}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- RunPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(context.Context, net.Destination) (PacketEndpoint, error) {
			return PacketEndpoint{Reader: leg, Writer: writer, Abort: leg.Abort}, nil
		})
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("packet writer was not reached")
	}
	if source.reads.Load() != 1 {
		t.Fatalf("read ahead under pressure: %d", source.reads.Load())
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, context.Canceled) {
			t.Fatalf("result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write did not unblock")
	}
	if !leg.exited.Load() {
		t.Fatal("reply worker was not joined")
	}
}

func (s *scriptedPacketSource) WritePacket(p []byte, dest net.Destination) (int, error) {
	s.mu.Lock()
	s.written = append(s.written, dest)
	s.mu.Unlock()
	return len(p), nil
}

func (s *scriptedPacketSource) Abort()                           { s.once.Do(func() { close(s.done) }) }
func (s *scriptedPacketSource) SetWriteDeadline(time.Time) error { s.deadlines.Add(1); return nil }

type scriptedPacketLeg struct {
	mu     sync.Mutex
	dests  []net.Destination
	done   chan struct{}
	once   sync.Once
	exited atomic.Bool
}

func (l *scriptedPacketLeg) ReadPacket([]byte) (int, net.Destination, error) {
	<-l.done
	l.exited.Store(true)
	return 0, net.Destination{}, io.EOF
}

func (l *scriptedPacketLeg) WritePacket(p []byte, dest net.Destination) (int, error) {
	l.mu.Lock()
	l.dests = append(l.dests, dest)
	l.mu.Unlock()
	return len(p), nil
}
func (l *scriptedPacketLeg) Abort() { l.once.Do(func() { close(l.done) }) }

func TestPacketAssociationKeepsOneLegAndDestinations(t *testing.T) {
	a := net.UDPDestination(net.LocalHostIP, 10001)
	b := net.UDPDestination(net.LocalHostIP, 10002)
	source := &scriptedPacketSource{packets: []net.Destination{a, b}, done: make(chan struct{})}
	leg := &scriptedPacketLeg{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var preparations atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- RunPacketAssociation(ctx, PacketEndpoint{Reader: source, Writer: source, Abort: source.Abort, SetWriteDeadline: source.SetWriteDeadline}, func(_ context.Context, first net.Destination) (PacketEndpoint, error) {
			if first != a {
				return PacketEndpoint{}, errors.New("wrong first route")
			}
			preparations.Add(1)
			return PacketEndpoint{Reader: leg, Writer: leg, Abort: leg.Abort}, nil
		})
	}()
	deadline := time.After(time.Second)
	for {
		leg.mu.Lock()
		count := len(leg.dests)
		leg.mu.Unlock()
		if count == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("two destination writes did not complete")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
	if preparations.Load() != 1 {
		t.Fatalf("prepared %d legs", preparations.Load())
	}
	leg.mu.Lock()
	defer leg.mu.Unlock()
	if leg.dests[0] != a || leg.dests[1] != b {
		t.Fatalf("destinations=%v", leg.dests)
	}
	if !leg.exited.Load() {
		t.Fatal("reply reader not joined")
	}
}
