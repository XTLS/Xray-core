package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func livePercentileReport(t *testing.T, label string, samples []time.Duration) {
	t.Helper()
	if len(samples) == 0 {
		t.Logf("%-36s no samples", label)
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	q := func(p float64) time.Duration {
		return samples[min(int(p*float64(len(samples))), len(samples)-1)]
	}
	t.Logf("%-36s n=%d p50=%v p95=%v p99=%v max=%v",
		label, len(samples), q(0.50), q(0.95), q(0.99), samples[len(samples)-1])
}

func TestLiveDrivePercentiles(t *testing.T) {
	config := liveDriveConfig(t)
	root, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := root.session().(*driveStorage)
	defer store.Close()

	ctx := context.Background()
	const n = 60
	inlineDesc := strings.Repeat("a", 10<<10)
	body := make([]byte, 256<<10)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}

	inlineID, err := store.makeSlot(ctx, "percentiles/inline")
	if err != nil {
		t.Fatal(err)
	}
	defer store.deleteID(ctx, flatten("percentiles/inline"), inlineID)
	mediaID, err := store.makeSlot(ctx, "percentiles/media")
	if err != nil {
		t.Fatal(err)
	}
	defer store.deleteID(ctx, flatten("percentiles/media"), mediaID)
	if err := store.setSlot(ctx, mediaID, "media", body); err != nil {
		t.Fatal(err)
	}

	measure := func(label string, parallelism int, op func() error) {
		var mu sync.Mutex
		samples := make([]time.Duration, 0, n)
		var wg sync.WaitGroup
		per := n / parallelism
		for w := 0; w < parallelism; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < per; i++ {
					start := time.Now()
					err := op()
					elapsed := time.Since(start)
					if err != nil {
						t.Errorf("%s: %v", label, err)
						continue
					}
					mu.Lock()
					samples = append(samples, elapsed)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		livePercentileReport(t, fmt.Sprintf("%s (p=%d)", label, parallelism), samples)
	}

	for _, p := range []int{1, 8} {
		measure("inline setSlot 10KiB", p, func() error {
			return store.setSlot(ctx, inlineID, inlineDesc, nil)
		})
		measure("media setSlot 256KiB", p, func() error {
			return store.setSlot(ctx, mediaID, "media", body)
		})
		measure("readDescription", p, func() error {
			_, err := store.readDescription(ctx, mediaID)
			return err
		})
		measure("readBody 256KiB", p, func() error {
			_, err := store.readBody(ctx, mediaID)
			return err
		})
	}
}

func TestLiveDriveLatencyUnderLoad(t *testing.T) {
	config := liveDriveConfig(t)
	config.Concurrency = 64
	config.FlushIntervalMs = 10
	config.MaxPollIntervalMs = 200
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
	}

	run := func(withBulk bool) []time.Duration {
		client, server, cleanup := pairWith(t, settings)
		defer cleanup()
		if err := server.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
			t.Fatal(err)
		}

		var writeMu sync.Mutex
		writeFrame := func(kind byte, payload []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			var header [5]byte
			header[0] = kind
			binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
			if _, err := client.Write(header[:]); err != nil {
				return err
			}
			_, err := client.Write(payload)
			return err
		}
		readFrame := func() (byte, []byte, error) {
			var header [5]byte
			if _, err := io.ReadFull(server, header[:]); err != nil {
				return 0, nil, err
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
			if _, err := io.ReadFull(server, payload); err != nil {
				return 0, nil, err
			}
			return header[0], payload, nil
		}

		markers := make(chan time.Duration, 5)
		bulkTime := make(chan time.Duration, 1)
		go func() {
			var bulkRecv int
			var bulkStart time.Time
			for {
				kind, payload, err := readFrame()
				if err != nil {
					return
				}
				if kind == 1 {
					if bulkRecv == 0 {
						bulkStart = time.Now()
					}
					bulkRecv += len(payload)
					if bulkRecv == 8<<20 {
						bulkTime <- time.Since(bulkStart)
					}
				}
				if kind == 2 && len(payload) == 16 {
					sent := int64(binary.BigEndian.Uint64(payload[:8]))
					markers <- time.Since(time.Unix(0, sent))
				}
			}
		}()

		bulkDone := make(chan struct{})
		if withBulk {
			go func() {
				defer close(bulkDone)
				chunk := make([]byte, 64<<10)
				for i := 0; i < 128; i++ {
					if err := writeFrame(1, chunk); err != nil {
						t.Errorf("bulk frame: %v", err)
						return
					}
				}
			}()
			time.Sleep(3 * time.Second)
		}
		for i := 0; i < 5; i++ {
			var payload [16]byte
			binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixNano()))
			if err := writeFrame(2, payload[:]); err != nil {
				t.Fatalf("marker frame: %v", err)
			}
			if i < 4 {
				time.Sleep(2 * time.Second)
			}
		}
		if withBulk {
			<-bulkDone
		}
		out := make([]time.Duration, 0, 5)
		for i := 0; i < 5; i++ {
			select {
			case d := <-markers:
				out = append(out, d)
			case <-time.After(30 * time.Second):
				t.Fatal("marker did not arrive")
			}
		}
		if withBulk {
			select {
			case d := <-bulkTime:
				t.Logf("bulk throughput: %.2f MiB/s", 8/d.Seconds())
			case <-time.After(60 * time.Second):
				t.Log("bulk throughput: bulk did not complete")
			}
		}
		return out
	}

	t.Log("marker one-way latency with no bulk:")
	for i, d := range run(false) {
		t.Logf("  marker %d: %v", i+1, d.Round(time.Millisecond))
	}
	t.Log("marker one-way latency under 8MiB bulk:")
	for i, d := range run(true) {
		t.Logf("  marker %d: %v", i+1, d.Round(time.Millisecond))
	}
}
