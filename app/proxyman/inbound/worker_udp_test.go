package inbound

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
)

func TestRetiredUDPPeerDoesNotRemoveItsReplacement(t *testing.T) {
	w := &udpWorker{
		ctx:        context.Background(),
		address:    net.LocalHostIP,
		activeConn: make(map[connID]*udpConn),
	}
	w.checker = &task.Periodic{Interval: time.Hour, Execute: w.clean}
	defer w.checker.Close()

	id := connID{src: net.UDPDestination(net.LocalHostIP, 11600)}
	old, _ := w.getConnection(id)
	old.Close()
	current, existed := w.getConnection(id)
	if current == old || existed {
		t.Fatal("expected a new peer connection after close")
	}
	defer current.Close()

	w.removeConn(id, old)
	if got, existed := w.getConnection(id); got != current || !existed {
		t.Fatal("the old cleanup removed the replacement")
	}

	packet := buf.FromBytes([]byte("reply"))
	destination := net.UDPDestination(net.LocalHostIP, 11601)
	packet.UDP = &destination
	current.enqueue(packet)
	batch, err := current.ReadMultiBuffer()
	defer buf.ReleaseMulti(batch)
	if err != nil || len(batch) != 1 || string(batch[0].Bytes()) != "reply" || batch[0].UDP == nil || *batch[0].UDP != destination {
		t.Fatalf("unexpected datagram from replacement: %v, %v", batch, err)
	}

	finished := make(chan error, 1)
	go func() {
		mb, err := current.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		finished <- err
	}()
	current.Close()
	select {
	case err := <-finished:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read after peer retirement: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader stayed blocked after peer retirement")
	}
}
