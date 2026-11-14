package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

const liveSecretsEnv = "XRAY_XDRIVE_DRIVE_SECRETS"

func liveDriveConfig(t *testing.T) *Config {
	t.Helper()

	path := os.Getenv(liveSecretsEnv)
	if path == "" {
		t.Skipf("set %s to run this test", liveSecretsEnv)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var secrets struct {
		Folder       string `json:"folder"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(payload, &secrets); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	config := &Config{
		RemoteFolder:      secrets.Folder,
		Service:           "google-drive",
		Secrets:           []string{secrets.ClientID, secrets.ClientSecret, secrets.RefreshToken},
		SegmentBytes:      256 * 1024,
		FlushIntervalMs:   100,
		PollIntervalMs:    500,
		MaxPollIntervalMs: 2000,
		SessionTtlSeconds: 120,
	}
	if raw := os.Getenv("XRAY_XDRIVE_LIVE_SEGMENT"); raw != "" {
		config.SegmentBytes = uint32(envInt(t, "XRAY_XDRIVE_LIVE_SEGMENT"))
	}
	if raw := os.Getenv("XRAY_XDRIVE_LIVE_CONCURRENCY"); raw != "" {
		config.Concurrency = uint32(envInt(t, "XRAY_XDRIVE_LIVE_CONCURRENCY"))
	}

	storage, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	defer storage.Close()
	for _, dir := range []string{sessionsDir, streamsDir} {
		if err := storage.Delete(context.Background(), dir); err != nil {
			t.Fatalf("clearing %s: %v", dir, err)
		}
	}

	return config
}

func envInt(t *testing.T, name string) int {
	t.Helper()

	parsed, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return parsed
}

func TestLiveDriveStorage(t *testing.T) {
	config := liveDriveConfig(t)
	storage, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	name := "streams/livetest/c2s/000000000.seg"
	payload := []byte("xdrive over a real remote storage service")
	defer storage.Delete(ctx, "streams/livetest")

	start := time.Now()
	if err := storage.Put(ctx, name, payload); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Logf("Put took %v", time.Since(start))

	start = time.Now()
	names, err := storage.List(ctx, "streams/livetest/c2s")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("List took %v", time.Since(start))
	if len(names) != 1 || names[0].Name != "000000000.seg" {
		t.Fatalf("List returned %v, want one segment", names)
	}

	start = time.Now()
	got, err := storage.Get(ctx, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	t.Logf("Get took %v", time.Since(start))
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}

	if _, err := storage.Get(ctx, "streams/livetest/c2s/000000009.seg"); err != errNotFound {
		t.Fatalf("Get returned %v, want errNotFound", err)
	}

	if err := storage.Delete(ctx, "streams/livetest"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	names, err = storage.List(ctx, "streams/livetest/c2s")
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("List after delete returned %v", names)
	}
}

func TestLiveDriveTransport(t *testing.T) {
	config := liveDriveConfig(t)
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
	}

	client, server, cleanup := pairWith(t, streamSettings)
	defer cleanup()

	start := time.Now()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")
	t.Logf("client to server round took %v", time.Since(start))

	start = time.Now()
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")
	t.Logf("server to client round took %v", time.Since(start))

	size := 400000
	if raw := os.Getenv("XRAY_XDRIVE_LIVE_BYTES"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("XRAY_XDRIVE_LIVE_BYTES: %v", err)
		}
		size = parsed
	}
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	start = time.Now()
	go func() {
		client.Write(payload)
	}()
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	elapsed := time.Since(start)
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	t.Logf("%d bytes took %v (%.1f KiB/s)", len(payload), elapsed,
		float64(len(payload))/1024/elapsed.Seconds())
}

func TestLiveDriveParallelPut(t *testing.T) {
	config := liveDriveConfig(t)
	storage, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	defer storage.Delete(ctx, "streams/benchtest")

	chunk := make([]byte, 256*1024)
	if _, err := rand.Read(chunk); err != nil {
		t.Fatalf("rand: %v", err)
	}

	if err := storage.Put(ctx, "streams/benchtest/warmup", chunk); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	start := time.Now()
	for i := 0; i < 4; i++ {
		if err := storage.Put(ctx, fmt.Sprintf("streams/benchtest/seq%d", i), chunk); err != nil {
			t.Fatalf("sequential put: %v", err)
		}
	}
	sequential := time.Since(start)
	t.Logf("4 sequential puts of 256 KiB: %v (%.1f KiB/s)",
		sequential, float64(4*len(chunk))/1024/sequential.Seconds())

	start = time.Now()
	var wg sync.WaitGroup
	failures := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			failures[i] = storage.Put(ctx, fmt.Sprintf("streams/benchtest/par%d", i), chunk)
		}(i)
	}
	wg.Wait()
	parallel := time.Since(start)
	for _, err := range failures {
		if err != nil {
			t.Fatalf("parallel put: %v", err)
		}
	}
	t.Logf("8 parallel puts of 256 KiB: %v (%.1f KiB/s)",
		parallel, float64(8*len(chunk))/1024/parallel.Seconds())

	start = time.Now()
	names, err := storage.List(ctx, "streams/benchtest")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("List of %d objects took %v", len(names), time.Since(start))

	start = time.Now()
	wg = sync.WaitGroup{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			storage.Get(ctx, fmt.Sprintf("streams/benchtest/par%d", i))
		}(i)
	}
	wg.Wait()
	download := time.Since(start)
	t.Logf("8 parallel gets of 256 KiB: %v (%.1f KiB/s)",
		download, float64(8*len(chunk))/1024/download.Seconds())
}

func TestLiveDriveSegmentSweep(t *testing.T) {
	config := liveDriveConfig(t)
	storage, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	defer storage.Delete(ctx, "streams/sweeptest")

	const total = 1024 * 1024
	for _, size := range []int{64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024} {
		chunk := make([]byte, size)
		if _, err := rand.Read(chunk); err != nil {
			t.Fatalf("rand: %v", err)
		}
		count := total / size

		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				storage.Put(ctx, fmt.Sprintf("streams/sweeptest/s%d-%d", size, i), chunk)
			}(i)
		}
		wg.Wait()
		elapsed := time.Since(start)

		t.Logf("%4d KiB x %2d = 1 MiB in %8v -> %6.1f KiB/s",
			size/1024, count, elapsed.Round(time.Millisecond),
			float64(total)/1024/elapsed.Seconds())
	}
}

func TestLiveDriveListLag(t *testing.T) {
	config := liveDriveConfig(t)
	storage, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	defer storage.Delete(ctx, "streams/lagtest")

	const rounds = 6
	var worst time.Duration

	for i := 0; i < rounds; i++ {
		name := fmt.Sprintf("streams/lagtest/round%d/000000000.seg", i)
		if err := storage.Put(ctx, name, []byte("probe")); err != nil {
			t.Fatalf("Put: %v", err)
		}

		start := time.Now()
		var lag time.Duration
		for {
			names, err := storage.List(ctx, fmt.Sprintf("streams/lagtest/round%d", i))
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(names) == 1 {
				lag = time.Since(start)
				break
			}
			if time.Since(start) > 30*time.Second {
				t.Fatalf("round %d: the object never showed up in a listing", i)
			}
		}
		if lag > worst {
			worst = lag
		}
		t.Logf("round %d: the object became listable after %v", i, lag.Round(time.Millisecond))
	}
	t.Logf("worst listing lag: %v", worst.Round(time.Millisecond))
}

func TestLiveDriveLatencyFloor(t *testing.T) {
	config := liveDriveConfig(t)
	root, err := newDriveStorage(&internet.MemoryStreamConfig{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := root.session().(*driveStorage)
	defer store.Close()

	ctx := context.Background()
	const probe = "latency-floor/probe"
	id, err := store.makeSlot(ctx, probe)
	if err != nil {
		t.Fatal(err)
	}
	defer store.deleteID(ctx, flatten(probe), id)

	small := newSlotFrame(1, slotInline, randomPayload(700)).encode()
	large := newSlotFrame(1, slotInline, randomPayload(slotInlineLimit)).encode()
	file := store.filesURL + "/" + url.PathEscape(id)

	type sample struct {
		total, ttfb time.Duration
		reused      bool
	}
	measure := func(label string, op func(context.Context) error) []sample {
		var out []sample
		for i := 0; i < 28; i++ {
			var wrote, first time.Time
			var reused bool
			trace := &httptrace.ClientTrace{
				GotConn:              func(info httptrace.GotConnInfo) { reused = info.Reused },
				WroteRequest:         func(httptrace.WroteRequestInfo) { wrote = time.Now() },
				GotFirstResponseByte: func() { first = time.Now() },
			}
			start := time.Now()
			err := op(httptrace.WithClientTrace(ctx, trace))
			total := time.Since(start)
			if err != nil {
				t.Logf("latency-floor: %s sample failed: %v", label, err)
			} else if i >= 3 {
				var ttfb time.Duration
				if !wrote.IsZero() && !first.IsZero() {
					ttfb = first.Sub(wrote)
				}
				out = append(out, sample{total, ttfb, reused})
			}
			time.Sleep(250 * time.Millisecond)
		}
		return out
	}
	report := func(label string, s []sample) time.Duration {
		if len(s) == 0 {
			t.Logf("latency-floor: %-30s no samples", label)
			return 0
		}
		totals := make([]time.Duration, len(s))
		ttfbs := make([]time.Duration, len(s))
		reused := 0
		for i, x := range s {
			totals[i], ttfbs[i] = x.total, x.ttfb
			if x.reused {
				reused++
			}
		}
		sort.Slice(totals, func(a, b int) bool { return totals[a] < totals[b] })
		sort.Slice(ttfbs, func(a, b int) bool { return ttfbs[a] < ttfbs[b] })
		q := func(v []time.Duration, p float64) time.Duration { return v[min(int(p*float64(len(v))), len(v)-1)] }
		t.Logf("latency-floor: %-30s n=%d min=%v p50=%v p95=%v ttfb_p50=%v reused=%d/%d",
			label, len(s), totals[0], q(totals, 0.5), q(totals, 0.95), q(ttfbs, 0.5), reused, len(s))
		return q(ttfbs, 0.5)
	}
	patch := func(target string, doc map[string]any) func(context.Context) error {
		body, _ := json.Marshal(doc)
		return func(ctx context.Context) error {
			status, reply, err := store.do(ctx, http.MethodPatch, target, "application/json; charset=UTF-8", body)
			if err == nil && status != http.StatusOK {
				err = fmt.Errorf("status %d: %s", status, reply)
			}
			return err
		}
	}
	get := func(target string) func(context.Context) error {
		return func(ctx context.Context) error {
			status, reply, err := store.do(ctx, http.MethodGet, target, "", nil)
			if err == nil && status != http.StatusOK {
				err = fmt.Errorf("status %d: %s", status, reply)
			}
			return err
		}
	}

	proto := ""
	netFloor := report("net floor (401, no auth)", measure("net", func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/drive/v3/about?fields=user", nil)
		if err != nil {
			return err
		}
		resp, err := store.client.Do(req)
		if err != nil {
			return err
		}
		proto = resp.Proto
		io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	}))
	t.Logf("latency-floor: negotiated protocol %s", proto)
	readDesc := report("GET description (prod)", measure("get", func(ctx context.Context) error {
		_, err := store.readDescription(ctx, id)
		return err
	}))
	report("GET fields=id", measure("getid", get(file+"?fields=id&supportsAllDrives=true")))
	report("GET description, no allDrives", measure("getnoall", get(file+"?fields=description")))
	write1k := report("PATCH inline 1 KB (prod)", measure("p1k", func(ctx context.Context) error {
		return store.setSlot(ctx, id, small, nil)
	}))
	write14k := report("PATCH inline 14 KB (prod)", measure("p14k", func(ctx context.Context) error {
		return store.setSlot(ctx, id, large, nil)
	}))
	report("PATCH 1 KB, no allDrives", measure("pnoall", patch(file+"?fields=id", map[string]any{"description": small})))
	report("PATCH name 200 B", measure("pname", patch(file+"?fields=id&supportsAllDrives=true", map[string]any{"name": strings.Repeat("n", 200)})))
	report("PATCH appProperties 100 B", measure("pprop", patch(file+"?fields=id&supportsAllDrives=true", map[string]any{"appProperties": map[string]string{"k": strings.Repeat("a", 100)}})))
	t.Logf("latency-floor: derived: write backend ~ %v, read backend ~ %v, 14 KB payload cost ~ %v",
		write1k-netFloor, readDesc-netFloor, write14k-write1k)
}
