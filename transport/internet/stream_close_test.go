package internet

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var closeTestProtocolID atomic.Uint64

func closeTestProtocol() string {
	return fmt.Sprintf("stream-close-test-%d", closeTestProtocolID.Add(1))
}

func TestMemoryStreamConfigCloseOnce(t *testing.T) {
	protocol := closeTestProtocol()
	want := stderrors.New("transport close failed")
	var calls atomic.Int32
	var closedInCallback atomic.Bool
	config := &MemoryStreamConfig{ProtocolName: protocol}
	if err := RegisterTransportCloser(protocol, func(s *MemoryStreamConfig) error {
		calls.Add(1)
		closedInCallback.Store(s.IsClosed())
		return want
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := config.Close(); !stderrors.Is(err, want) {
				t.Errorf("Close error = %v, want %v", err, want)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("transport closer calls = %d, want 1", got)
	}
	if !closedInCallback.Load() || !config.IsClosed() {
		t.Error("config was not marked closed before cleanup")
	}
}

func TestMemoryStreamConfigCloseIsolatesConfiguration(t *testing.T) {
	protocol := closeTestProtocol()
	first := &MemoryStreamConfig{ProtocolName: protocol}
	second := &MemoryStreamConfig{ProtocolName: protocol}
	seen := make(map[*MemoryStreamConfig]int)
	if err := RegisterTransportCloser(protocol, func(s *MemoryStreamConfig) error {
		seen[s]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if !first.IsClosed() || second.IsClosed() || seen[first] != 1 || seen[second] != 0 {
		t.Fatal("closing one config affected another using the same protocol")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if seen[first] != 1 || seen[second] != 1 {
		t.Errorf("cleanup did not receive each exact config: %v", seen)
	}
}

func TestDialRejectsClosedMemoryStreamConfig(t *testing.T) {
	protocol := closeTestProtocol()
	var calls atomic.Int32
	if err := RegisterTransportDialer(protocol, func(context.Context, net.Destination, *MemoryStreamConfig) (stat.Connection, error) {
		calls.Add(1)
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	config := &MemoryStreamConfig{ProtocolName: protocol}
	if err := config.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(context.Background(), net.TCPDestination(net.ParseAddress("127.0.0.1"), 80), config); err == nil {
		t.Error("Dial accepted a closed config")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("closed config reached transport dialer %d times", got)
	}
}
