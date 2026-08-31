package proxy

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestVisionTrafficStateConcurrentPacketFiltering(t *testing.T) {
	state := NewTrafficState(make([]byte, 16))
	state.NumberOfPacketToFilter = 1 << 30
	state.Outbound.IsPadding = false
	writer := NewVisionWriter(buf.NewWriter(io.Discard), state, true, context.Background(), nil, nil, nil)

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for range 10_000 {
			buffer := buf.New()
			_, _ = buffer.Write([]byte{0})
			if err := writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
				t.Errorf("Vision writer: %v", err)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range 10_000 {
			buffer := buf.New()
			_, _ = buffer.Write([]byte{0})
			multiBuffer := buf.MultiBuffer{buffer}
			XtlsFilterTls(multiBuffer, state, context.Background())
			buf.ReleaseMulti(multiBuffer)
		}
	}()
	close(start)
	workers.Wait()
	if got, want := state.NumberOfPacketToFilter, (1<<30)-20_000; got != want {
		t.Fatalf("NumberOfPacketToFilter = %d, want %d", got, want)
	}
}

func TestVisionTrafficStateConcurrentTLSClassification(t *testing.T) {
	state := NewTrafficState(make([]byte, 16))
	serverHello := make([]byte, 90)
	copy(serverHello, TlsServerHandShakeStart)
	serverHello[4] = 85
	serverHello[5] = TlsHandshakeTypeServerHello
	serverHello[43] = 0
	serverHello[44] = 0x13
	serverHello[45] = 0x01
	copy(serverHello[50:], Tls13SupportedVersions)

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 100 {
				buffer := buf.New()
				_, _ = buffer.Write(serverHello)
				multiBuffer := buf.MultiBuffer{buffer}
				XtlsFilterTls(multiBuffer, state, context.Background())
				buf.ReleaseMulti(multiBuffer)
			}
		}()
	}
	close(start)
	workers.Wait()
	if !state.IsTLS || !state.IsTLS12orAbove || !state.EnableXtls {
		t.Fatalf("unexpected TLS classification: IsTLS=%t IsTLS12orAbove=%t EnableXtls=%t", state.IsTLS, state.IsTLS12orAbove, state.EnableXtls)
	}
	if got, want := state.Cipher, uint16(0x1301); got != want {
		t.Fatalf("Cipher = %#x, want %#x", got, want)
	}
	if got := state.RemainingServerHello; got != 0 {
		t.Fatalf("RemainingServerHello = %d, want 0", got)
	}
}
