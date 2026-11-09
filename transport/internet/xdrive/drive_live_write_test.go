package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func TestLiveDriveWriteSweep(t *testing.T) {
	config := liveDriveConfig(t)
	root, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := root.session().(*driveStorage)
	defer store.Close()

	ctx := context.Background()
	inlineID, err := store.makeSlot(ctx, "sweep/inline")
	if err != nil {
		t.Fatal(err)
	}
	defer store.deleteID(ctx, flatten("sweep/inline"), inlineID)
	mediaID, err := store.makeSlot(ctx, "sweep/media")
	if err != nil {
		t.Fatal(err)
	}
	defer store.deleteID(ctx, flatten("sweep/media"), mediaID)

	desc := strings.Repeat("a", 10<<10)
	body := make([]byte, 256<<10)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	kinds := []struct {
		name string
		op   func(context.Context) error
	}{
		{"inline 10KiB", func(ctx context.Context) error { return store.setSlot(ctx, inlineID, desc, nil) }},
		{"media 256KiB", func(ctx context.Context) error { return store.setSlot(ctx, mediaID, "media", body) }},
	}

	for _, p := range []int{1, 2, 3, 4, 6, 8, 12} {
		for _, kind := range kinds {
			levelCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			thr0 := store.throttled()
			var mu sync.Mutex
			var samples []time.Duration
			success := 0
			var wg sync.WaitGroup
			per := 40 / p
			levelStart := time.Now()
			for w := 0; w < p; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < per; i++ {
						if levelCtx.Err() != nil {
							return
						}
						start := time.Now()
						if err := kind.op(levelCtx); err != nil {
							continue
						}
						mu.Lock()
						samples = append(samples, time.Since(start))
						success++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			wall := time.Since(levelStart)
			cancel()
			if len(samples) == 0 {
				t.Logf("sweep p=%-2d %-14s writes=0 wall=%v no samples", p, kind.name, wall.Round(time.Millisecond))
				continue
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			q := func(f float64) time.Duration {
				return samples[min(int(f*float64(len(samples))), len(samples)-1)]
			}
			t.Logf("sweep p=%-2d %-14s writes=%d wall=%v writes/s=%.2f p50=%v p95=%v p99=%v max=%v throttled=+%d",
				p, kind.name, success, wall.Round(time.Millisecond), float64(success)/wall.Seconds(),
				q(0.50), q(0.95), q(0.99), samples[len(samples)-1], store.throttled()-thr0)
		}
	}
}

func TestLiveDriveBrowsingExchanges(t *testing.T) {
	config := liveDriveConfig(t)
	config.Concurrency = 64
	config.FlushIntervalMs = 10
	config.MaxPollIntervalMs = 200
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
	}

	var slotWrites, ackWrites, announceWrites, reads atomic.Int64
	testDriveIO = func(method, target string, body []byte) {
		switch method {
		case http.MethodGet:
			reads.Add(1)
		case http.MethodPatch:
			var doc struct {
				Description string `json:"description"`
			}
			if json.Unmarshal(body, &doc) != nil {
				return
			}
			if _, ok := decodeSlot(doc.Description); ok {
				slotWrites.Add(1)
				return
			}
			if _, err := strconv.ParseInt(doc.Description, 10, 64); err == nil && doc.Description != "" {
				ackWrites.Add(1)
				return
			}
			slotWrites.Add(1)
		case http.MethodPost, http.MethodPut:
			if method == http.MethodPut || strings.Contains(target, "/upload") {
				slotWrites.Add(1)
				return
			}
			var doc struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(body, &doc) == nil && strings.HasPrefix(doc.Name, sessionsDir+flatSeparator) {
				announceWrites.Add(1)
				return
			}
			slotWrites.Add(1)
		}
	}
	defer func() { testDriveIO = nil }()

	client, server, cleanup := pairWith(t, settings)
	if err := server.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	answer := randomPayload(30 << 10)
	latencies := make([]time.Duration, 0, 40)
	for i := 0; i < 40; i++ {
		start := time.Now()
		request := randomPayload(500)
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		gotRequest := make([]byte, len(request))
		if _, err := io.ReadFull(server, gotRequest); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotRequest, request) {
			t.Fatal("the request came back changed")
		}
		if _, err := server.Write(answer); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(answer))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, answer) {
			t.Fatal("the answer came back changed")
		}
		latencies = append(latencies, time.Since(start))
		if i < 39 {
			time.Sleep(400 * time.Millisecond)
		}
	}
	cleanup()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	q := func(f float64) time.Duration {
		return latencies[min(int(f*float64(len(latencies))), len(latencies)-1)]
	}
	t.Logf("browsing: exchanges=%d p50=%v p95=%v max=%v",
		len(latencies), q(0.50), q(0.95), latencies[len(latencies)-1])
	total := slotWrites.Load() + ackWrites.Load() + announceWrites.Load()
	share := float64(0)
	if total > 0 {
		share = 100 * float64(ackWrites.Load()) / float64(total)
	}
	t.Logf("browsing writes: slot-data=%d watermark-ack=%d announcement=%d total=%d ack-share=%.1f%% reads=%d",
		slotWrites.Load(), ackWrites.Load(), announceWrites.Load(), total, share, reads.Load())
}
