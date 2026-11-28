package udp

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

func TestPacketInboxRetiresExactRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	leg, end := context.WithCancel(ctx)
	defer end()
	inbox := NewPacketInbox(128)
	defer inbox.Close()
	inbox.AttachRoute(leg)

	add := func(data string) {
		t.Helper()
		payload := buf.New()
		payload.WriteString(data)
		if err := inbox.Put(ctx, buf.MultiBuffer{payload}); err != nil {
			t.Fatal(err)
		}
	}
	add("packet admitted by old route")
	end()
	add("association packet after retirement")
	inbox.RetireRoute()

	packet, err := inbox.Take(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(packet)
	if len(packet) != 1 || string(packet[0].Bytes()) != "association packet after retirement" {
		t.Fatalf("unexpected replacement input: %v", packet)
	}
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	if extra, err := inbox.Take(ctx, timer.C); !errors.Is(err, buf.ErrReadTimeout) {
		buf.ReleaseMulti(extra)
		t.Fatalf("retired packet was not removed: %v", err)
	}
}

func TestPacketInboxCloseWakesProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	inbox := NewPacketInbox(0)
	defer inbox.Close()
	waiting := observeInboxWait(inbox)
	if err := inbox.Put(ctx, inboxTestPacket()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- inbox.Put(ctx, inboxTestPacket()) }()
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("producer did not wait on a full inbox")
	}
	inbox.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("pending producer returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal("producer did not leave the closed inbox")
	}
}

func TestPacketInboxCanceledOfferLeavesAdmittedPacket(t *testing.T) {
	inbox := NewPacketInbox(0)
	defer inbox.Close()
	waiting := observeInboxWait(inbox)
	inbox.AttachRoute(t.Context())
	if err := inbox.Put(t.Context(), inboxTestPacket()); err != nil {
		t.Fatal(err)
	}
	query, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- inbox.Put(query, inboxTestPacket()) }()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("query did not wait on a full inbox")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked query returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("query required another reader or send to wake")
	}
	packets, err := inbox.Take(t.Context(), nil)
	defer buf.ReleaseMulti(packets)
	if err != nil || len(packets) != 1 {
		t.Fatalf("queued packet was lost or duplicated: %d, %v", len(packets), err)
	}
}

func TestPacketInboxRetirementDropsBlockedOldAdmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	leg, end := context.WithCancel(ctx)
	defer end()
	inbox := NewPacketInbox(0)
	defer inbox.Close()
	waiting := observeInboxWait(inbox)
	inbox.AttachRoute(leg)
	counter := new(stats.Counter)
	inbox.BindUplinkCounter(leg, counter)
	if err := inbox.Put(ctx, inboxTestPacket()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- inbox.Put(ctx, inboxTestPacket()) }()
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("producer did not wait on a full inbox")
	}
	if got := counter.Value(); got != 2 {
		t.Fatalf("counted %d bytes with one buffered and one attempted, want 2", got)
	}
	end()
	inbox.RetireRoute()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("producer stayed blocked after retirement")
	}
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	if packets, err := inbox.Take(ctx, timer.C); !errors.Is(err, buf.ErrReadTimeout) {
		buf.ReleaseMulti(packets)
		t.Fatalf("replacement took a packet offered to the retired route: %v", err)
	}
}

func inboxTestPacket() buf.MultiBuffer {
	data := buf.New()
	data.WriteByte(1)
	return buf.MultiBuffer{data}
}

type inboxWaitObserver struct {
	sync.Locker
	waiting *signal.Notifier
}

func (l inboxWaitObserver) Unlock() {
	l.Locker.Unlock()
	l.waiting.Signal()
}

func observeInboxWait(inbox *PacketInbox) <-chan struct{} {
	waiting := signal.NewNotifier()
	inbox.room.L = inboxWaitObserver{Locker: &inbox.mu, waiting: waiting}
	return waiting.Wait()
}

func TestPacketInboxRouteTakesAvailableBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	route, cancelRoute := context.WithCancel(ctx)
	defer cancelRoute()
	inbox := NewPacketInbox(128)
	defer inbox.Close()
	for i := range byte(3) {
		b := buf.New()
		b.WriteByte(i)
		if err := inbox.Put(ctx, buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := inbox.Take(ctx, nil)
	defer buf.ReleaseMulti(first)
	if err != nil || len(first) != 1 || first[0].Bytes()[0] != 0 {
		t.Fatalf("first record: %v %v", first, err)
	}
	inbox.AttachRoute(route)
	batch, err := inbox.Take(route, nil)
	defer buf.ReleaseMulti(batch)
	if err != nil || len(batch) != 2 || batch[0].Bytes()[0] != 1 || batch[1].Bytes()[0] != 2 {
		t.Fatalf("queued batch: %v %v", batch, err)
	}
}
