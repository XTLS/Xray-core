package xdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

type fakeStore struct {
	server *httptest.Server

	mu       sync.Mutex
	objects  map[string][]byte
	needAuth string
	sawAuth  string
	tokens   int
}

func newFakeStore(t *testing.T) *fakeStore {
	t.Helper()

	store := &fakeStore{objects: make(map[string][]byte)}
	store.server = httptest.NewServer(http.HandlerFunc(store.handle))
	t.Cleanup(store.server.Close)
	return store
}

func (s *fakeStore) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		s.mu.Lock()
		s.tokens++
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok-fake", "expires_in": 3600,
		})
		return
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		s.mu.Lock()
		s.sawAuth = auth
		s.mu.Unlock()
	}
	if s.needAuth != "" && r.Header.Get("Authorization") != s.needAuth {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	key := strings.TrimPrefix(r.URL.Path, "/folder/")

	switch r.Method {
	case "PROPFIND":
		s.mu.Lock()
		var b strings.Builder
		for name := range s.objects {
			fmt.Fprintf(&b, "<d:href>/folder/%s</d:href>\n", name)
		}
		s.mu.Unlock()
		w.Write([]byte(b.String()))
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.objects[key] = body
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		s.mu.Lock()
		data, ok := s.objects[key]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(data)
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, key)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *fakeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

func (s *fakeStore) seenAuth() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sawAuth
}

func templateSettings(store *fakeStore, auth map[string]interface{}, secrets []string) *internet.MemoryStreamConfig {
	base := store.server.URL
	tmpl := map[string]interface{}{
		"flatten": true,
		"auth":    auth,
		"put":     map[string]interface{}{"method": "PUT", "url": base + "/folder/{name}"},
		"get":     map[string]interface{}{"method": "GET", "url": base + "/folder/{name}"},
		"delete":  map[string]interface{}{"method": "DELETE", "url": base + "/folder/{name}"},
		"list": map[string]interface{}{
			"method":     "PROPFIND",
			"url":        base + "/folder/",
			"namesRegex": `<d:href>/folder/([^<]+)</d:href>`,
		},
		"retry": map[string]interface{}{"status": []int{429, 500, 502, 503}},
	}
	raw, _ := json.Marshal(tmpl)
	return &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			RemoteFolder:      "folder",
			Service:           "template",
			Secrets:           secrets,
			Template:          string(raw),
			FlushIntervalMs:   5,
			PollIntervalMs:    5,
			MaxPollIntervalMs: 20,
			SessionTtlSeconds: 5,
		},
	}
}

func newTemplateBackend(t *testing.T, store *fakeStore, auth map[string]interface{}, secrets []string) *templateStorage {
	t.Helper()
	settings := templateSettings(store, auth, secrets)
	storage, err := newTemplateStorage(settings, settings.ProtocolSettings.(*Config))
	if err != nil {
		t.Fatalf("newTemplateStorage: %v", err)
	}
	return storage
}

func TestTemplateRoundTrip(t *testing.T) {
	store := newFakeStore(t)
	storage := newTemplateBackend(t, store, map[string]interface{}{"type": "none"}, nil)
	ctx := context.Background()

	if err := storage.Put(ctx, "streams/abc/c2s/000000000.seg", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := storage.Get(ctx, "streams/abc/c2s/000000000.seg")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("Get returned %q, want hello", data)
	}

	entries, err := storage.List(ctx, "streams/abc/c2s")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "000000000.seg" {
		t.Fatalf("List returned %v, want one segment", entries)
	}

	if _, err := storage.Get(ctx, "streams/abc/c2s/000000009.seg"); err != errNotFound {
		t.Fatalf("Get of a missing object returned %v, want errNotFound", err)
	}

	if err := storage.Delete(ctx, "streams/abc/c2s/000000000.seg"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if store.count() != 0 {
		t.Fatalf("store still holds %d objects", store.count())
	}
}

func TestTemplateListReturnsDirectChildren(t *testing.T) {
	store := newFakeStore(t)
	storage := newTemplateBackend(t, store, map[string]interface{}{"type": "none"}, nil)
	ctx := context.Background()

	for _, name := range []string{
		"streams/one/c2s/000000000.seg",
		"streams/one/s2c/000000000.seg",
		"streams/two/c2s/000000000.seg",
	} {
		if err := storage.Put(ctx, name, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", name, err)
		}
	}

	entries, err := storage.List(ctx, "streams")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %v, want the two session ids", entries)
	}
}

func TestTemplateBasicAuth(t *testing.T) {
	store := newFakeStore(t)
	store.needAuth = "Basic dXNlcjpwYXNz"
	auth := map[string]interface{}{"type": "basic", "username": "{secret0}", "password": "{secret1}"}
	storage := newTemplateBackend(t, store, auth, []string{"user", "pass"})

	if err := storage.Put(context.Background(), "sessions/a", []byte("x")); err != nil {
		t.Fatalf("Put with basic auth: %v", err)
	}
	if store.seenAuth() != "Basic dXNlcjpwYXNz" {
		t.Fatalf("server saw auth %q", store.seenAuth())
	}
}

func TestTemplateOAuth(t *testing.T) {
	store := newFakeStore(t)
	store.needAuth = "Bearer tok-fake"
	auth := map[string]interface{}{
		"type":     "oauth2",
		"tokenUrl": store.server.URL + "/token",
		"form":     map[string]interface{}{"grant_type": "refresh_token", "refresh_token": "{secret0}"},
		"header":   map[string]interface{}{"Authorization": "Bearer {token}"},
	}
	storage := newTemplateBackend(t, store, auth, []string{"refresh"})
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if err := storage.Put(ctx, fmt.Sprintf("sessions/s%d", i), nil); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if store.tokens != 1 {
		t.Fatalf("token endpoint was hit %d times, want 1", store.tokens)
	}
}

func TestTemplateTransport(t *testing.T) {
	store := newFakeStore(t)
	settings := templateSettings(store, map[string]interface{}{"type": "none"}, nil)

	client, server, cleanup := pairWith(t, settings)
	defer cleanup()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")

	payload := make([]byte, 300000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	go func() { client.Write(payload) }()

	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("payload mismatch at byte %d", i)
		}
	}
}

func TestTemplateConcurrency(t *testing.T) {
	store := newFakeStore(t)
	settings := templateSettings(store, map[string]interface{}{"type": "none"}, nil)

	var tmpl map[string]interface{}
	cfg := settings.ProtocolSettings.(*Config)
	if err := json.Unmarshal([]byte(cfg.Template), &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl["concurrency"] = 4
	raw, _ := json.Marshal(tmpl)
	cfg.Template = string(raw)

	storage, err := newTemplateStorage(settings, cfg)
	if err != nil {
		t.Fatalf("newTemplateStorage: %v", err)
	}
	if cap(storage.inflight) != 4 {
		t.Fatalf("inflight cap is %d, want 4 from the template", cap(storage.inflight))
	}
}

func TestTemplateConcurrencyDefault(t *testing.T) {
	store := newFakeStore(t)
	storage := newTemplateBackend(t, store, map[string]interface{}{"type": "none"}, nil)
	if cap(storage.inflight) != driveMaxInflight {
		t.Fatalf("default inflight cap is %d, want %d", cap(storage.inflight), driveMaxInflight)
	}
}
