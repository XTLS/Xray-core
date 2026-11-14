package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

const yandexBase = "https://webdav.yandex.ru"

func envUint(name string, def uint32) uint32 {
	if v := os.Getenv(name); v != "" {
		var n uint32
		fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			return n
		}
	}
	return def
}

func liveYandexSettings(t *testing.T) (*internet.MemoryStreamConfig, string, func()) {
	t.Helper()

	user := os.Getenv("XDRIVE_YANDEX_USER")
	pass := os.Getenv("XDRIVE_YANDEX_PASS")
	if user == "" || pass == "" {
		t.Skip("set XDRIVE_YANDEX_USER and XDRIVE_YANDEX_PASS to run this test")
	}

	folder := fmt.Sprintf("xdrive-live-%d", time.Now().UnixNano())
	dav := func(method, path string) int {
		req, _ := http.NewRequest(method, yandexBase+path, nil)
		req.SetBasicAuth(user, pass)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := dav("MKCOL", "/"+folder); code != 201 && code != 405 {
		t.Fatalf("MKCOL answered %d", code)
	}

	tmpl := map[string]interface{}{
		"flatten": true,
		"auth":    map[string]interface{}{"type": "basic", "username": "{secret0}", "password": "{secret1}"},
		"put":     map[string]interface{}{"method": "PUT", "url": yandexBase + "/{folder}/{name}"},
		"get":     map[string]interface{}{"method": "GET", "url": yandexBase + "/{folder}/{name}"},
		"delete":  map[string]interface{}{"method": "DELETE", "url": yandexBase + "/{folder}/{name}"},
		"list": map[string]interface{}{
			"method": "PROPFIND", "url": yandexBase + "/{folder}/",
			"headers": map[string]interface{}{"Depth": "1"}, "namesRegex": `<d:href>[^<]*/([^/<]+)</d:href>`,
		},
		"retry": map[string]interface{}{"status": []int{429, 500, 502, 503}},
	}
	raw, _ := json.Marshal(tmpl)
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			RemoteFolder:      folder,
			Service:           "template",
			Secrets:           []string{user, pass},
			Template:          string(raw),
			SegmentBytes:      262144,
			FlushIntervalMs:   100,
			PollIntervalMs:    300,
			MaxPollIntervalMs: 1500,
			SessionTtlSeconds: 120,
			Concurrency:       envUint("XDRIVE_LIVE_CONCURRENCY", 8),
		},
	}
	cleanup := func() { dav("DELETE", "/"+folder) }
	return settings, folder, cleanup
}

func TestLiveYandexStorage(t *testing.T) {
	settings, _, cleanup := liveYandexSettings(t)
	defer cleanup()

	storage, err := newTemplateStorage(settings, settings.ProtocolSettings.(*Config))
	if err != nil {
		t.Fatalf("newTemplateStorage: %v", err)
	}
	ctx := context.Background()

	name := "streams/live/c2s/000000000.seg"
	payload := []byte("xdrive over real yandex webdav")

	start := time.Now()
	if err := storage.Put(ctx, name, payload); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Logf("Put took %v", time.Since(start))

	start = time.Now()
	names, err := storage.List(ctx, "streams/live/c2s")
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
		t.Fatalf("Get returned %q", got)
	}

	if _, err := storage.Get(ctx, "streams/live/c2s/000000009.seg"); err != errNotFound {
		t.Fatalf("Get of a missing object returned %v, want errNotFound", err)
	}

	if err := storage.Delete(ctx, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestLiveYandexTransport(t *testing.T) {
	settings, _, cleanup := liveYandexSettings(t)
	defer cleanup()

	client, server, done := pairWith(t, settings)
	defer done()

	start := time.Now()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")
	t.Logf("client to server round took %v", time.Since(start))

	size := 1000000
	if raw := os.Getenv("XDRIVE_LIVE_BYTES"); raw != "" {
		fmt.Sscanf(raw, "%d", &size)
	}
	payload := make([]byte, size)
	rand.Read(payload)

	start = time.Now()
	go func() { client.Write(payload) }()
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
	t.Logf("%d bytes in %v -> %.1f KiB/s", len(payload), elapsed,
		float64(len(payload))/1024/elapsed.Seconds())
}
