package rawconn_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport/internet/rawconn"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type noopCounter struct{ stats.Counter }

func (noopCounter) Add(int64) int64  { return 0 }
func (noopCounter) Set(int64) int64  { return 0 }
func (noopCounter) Value() int64     { return 0 }

func TestIsRAW_plainTCP(t *testing.T) {
	conn := &stat.CounterConnection{
		Connection: &net.TCPConn{},
	}
	if !rawconn.IsRAW(conn) {
		t.Error("expected plain TCP conn to be RAW")
	}
}

func TestIsRAW_nilConn(t *testing.T) {
	if rawconn.IsRAW(nil) {
		t.Error("expected nil conn to not be RAW")
	}
}

func TestUnwrap_plainConn(t *testing.T) {
	conn := &net.TCPConn{}
	raw, readCounter, writeCounter := rawconn.Unwrap(conn)
	if raw != conn {
		t.Error("expected same conn back for unwrapped type")
	}
	if readCounter != nil {
		t.Error("expected nil read counter for unwrapped type")
	}
	if writeCounter != nil {
		t.Error("expected nil write counter for unwrapped type")
	}
}

func TestCopyIfExist_basicTransfer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	content := []byte("test data for copy")
	go func() {
		client.Write(content)
		client.Close()
	}()

	pipeR, pipeW := pipe.New(pipe.WithSizeLimit(32768))

	timer := signal.CancelAfterInactivity(context.Background(), func() {}, 10*time.Second)

	go func() {
		rawconn.CopyIfExist(context.Background(), server, nil, pipeW, timer, nil)
	}()

	mb, err := pipeR.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	got := make([]byte, mb.Len())
	mb.Copy(got)
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}
}
