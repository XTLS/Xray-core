package xmc

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// tickTestWriter records every batch the tick stream writes to the network.
type tickTestWriter struct {
	mu     sync.Mutex
	writes [][]byte
}

func (w *tickTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (w *tickTestWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.writes...)
}

func readTickBatch(t *testing.T, batch []byte) []*mcPacket {
	t.Helper()
	r := bytes.NewReader(batch)
	var packets []*mcPacket
	for r.Len() > 0 {
		packet, err := readPacket(r)
		if err != nil {
			t.Fatalf("parse tick batch: %v", err)
		}
		packets = append(packets, packet)
	}
	return packets
}

// tickPacketChannelAndPayload splits one custom payload into its channel name
// and the raw payload bytes that follow it.
func tickPacketChannelAndPayload(t *testing.T, packet *mcPacket) (string, []byte) {
	t.Helper()
	r := bytes.NewReader(packet.data)
	var channel String
	if err := channel.readFrom(r); err != nil {
		t.Fatalf("read tick packet channel: %v", err)
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read tick packet payload: %v", err)
	}
	return string(channel), payload
}

func collectTickData(t *testing.T, batches [][]byte) (data []byte, dataPackets, padding int) {
	t.Helper()
	for _, batch := range batches {
		for _, packet := range readTickBatch(t, batch) {
			channel, payload := tickPacketChannelAndPayload(t, packet)
			switch channel {
			case DefaultDataChannel:
				data = append(data, payload...)
				dataPackets++
			case DefaultPaddingChannel:
				padding++
			}
		}
	}
	return data, dataPackets, padding
}

// TestTickStreamIdleCadence pins the 20 Hz shape: an idle connection still
// emits one small padding frame per tick in both directions.
func TestTickStreamIdleCadence(t *testing.T) {
	writer := &tickTestWriter{}
	stream := newTickStream(nil, writer, true, configurationPacketIDs121, DefaultDataChannel, DefaultPaddingChannel)
	defer stream.Stop()

	time.Sleep(180 * time.Millisecond)
	stream.Stop()
	// Wait for an in-flight tick so the recorded batches are complete.
	_ = stream.Flush()

	batches := writer.snapshot()
	if len(batches) < 2 || len(batches) > 6 {
		t.Fatalf("got %d tick batches in 180ms, want about 3", len(batches))
	}
	for i, batch := range batches {
		packets := readTickBatch(t, batch)
		if len(packets) != 1 {
			t.Fatalf("idle tick %d wrote %d packets, want 1", i, len(packets))
		}
		if packets[0].packetID != configurationPacketIDs121.serverboundCustomPayload {
			t.Fatalf("idle tick %d packet id = %d", i, packets[0].packetID)
		}
		channel, _ := tickPacketChannelAndPayload(t, packets[0])
		if channel != DefaultPaddingChannel {
			t.Fatalf("idle tick %d channel = %q", i, channel)
		}
	}
}

// TestTickStreamSendsQueuedDataInOneTick checks that proxy data is queued and
// then emitted as one per-tick batch, split at maxPacketData boundaries.
func TestTickStreamSendsQueuedDataInOneTick(t *testing.T) {
	writer := &tickTestWriter{}
	stream := newTickStream(nil, writer, true, configurationPacketIDs121, DefaultDataChannel, DefaultPaddingChannel)
	defer stream.Stop()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	var (
		data        []byte
		dataPackets int
		padding     int
	)
	for time.Now().Before(deadline) {
		batches := writer.snapshot()
		if len(batches) > 0 {
			data, dataPackets, padding = collectTickData(t, batches)
			if len(data) >= len(payload) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !bytes.Equal(data, payload) {
		t.Fatalf("got %d payload bytes, want %d", len(data), len(payload))
	}
	wantPackets := (len(payload) + maxPacketData - 1) / maxPacketData
	if dataPackets != wantPackets {
		t.Fatalf("got %d data packets, want %d", dataPackets, wantPackets)
	}
	if padding < 1 {
		t.Fatal("the tick that carried data did not carry a padding frame")
	}
}

// TestTickStreamFlushWritesQueuedDataImmediately covers graceful close: data
// already accepted by Write must not wait for the next tick.
func TestTickStreamFlushWritesQueuedDataImmediately(t *testing.T) {
	writer := &tickTestWriter{}
	stream := newTickStream(nil, writer, true, configurationPacketIDs121, DefaultDataChannel, DefaultPaddingChannel)
	defer stream.Stop()

	payload := []byte("flush me")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.Flush(); err != nil {
		t.Fatal(err)
	}

	data, _, _ := collectTickData(t, writer.snapshot())
	if !bytes.Equal(data, payload) {
		t.Fatalf("flush delivered %q, want %q", data, payload)
	}
}
