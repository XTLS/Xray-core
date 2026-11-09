package xdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type fakeFile struct {
	id          string
	name        string
	data        []byte
	description string
}

type fakeDrive struct {
	server *httptest.Server

	mu          sync.Mutex
	files       map[string]*fakeFile
	nextID      int
	failOnce    map[string]bool
	failStatus  map[string]int
	failBody    map[string]string
	tokens      int
	tokenStatus int
	tokenBody   string
	uploadAt    []time.Time
	hosts       map[string]bool
}

func newFakeDrive(t *testing.T) *fakeDrive {
	t.Helper()

	drive := &fakeDrive{
		files:      make(map[string]*fakeFile),
		failOnce:   make(map[string]bool),
		failStatus: make(map[string]int),
		failBody:   make(map[string]string),
		hosts:      make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	record := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			drive.mu.Lock()
			drive.hosts[r.Host] = true
			drive.mu.Unlock()
			next(w, r)
		}
	}
	mux.HandleFunc("/token", record(drive.handleToken))
	mux.HandleFunc("/upload", record(drive.handleUpload))
	mux.HandleFunc("/upload/", record(drive.handleUpload))
	mux.HandleFunc("/files", record(drive.handleFiles))
	mux.HandleFunc("/files/", record(drive.handleFile))
	drive.server = httptest.NewServer(mux)

	resetSharedStorage()

	previous := []string{driveTokenURL, driveFilesURL, driveUploadURL}
	previousBackoff := driveInitialBackoff
	driveTokenURL = drive.server.URL + "/token"
	driveFilesURL = drive.server.URL + "/files"
	driveUploadURL = drive.server.URL + "/upload"
	driveInitialBackoff = 5 * time.Millisecond

	t.Cleanup(func() {
		driveTokenURL, driveFilesURL, driveUploadURL = previous[0], previous[1], previous[2]
		driveInitialBackoff = previousBackoff
		drive.server.Close()
		resetSharedStorage()
	})
	return drive
}

func (d *fakeDrive) handleToken(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.tokens++
	status, body := d.tokenStatus, d.tokenBody
	d.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		w.Write([]byte(body))
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "fake-token",
		"expires_in":   3600,
	})
}

func (d *fakeDrive) handleUpload(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.uploadAt = append(d.uploadAt, time.Now())
	d.mu.Unlock()
	if d.shouldFail("upload") {
		if status, body := d.failure("upload"); status != 0 {
			w.WriteHeader(status)
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	reader := multipart.NewReader(r.Body, params["boundary"])

	metaPart, err := reader.NextPart()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var metadata struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(metaPart).Decode(&metadata); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var data []byte
	if dataPart, err := reader.NextPart(); err == nil {
		data, _ = io.ReadAll(dataPart)
	}

	if id, ok := strings.CutPrefix(r.URL.Path, "/upload/"); ok {
		// an update of the body and description of a file
		d.mu.Lock()
		file := d.files[id]
		if file != nil {
			file.data, file.description = data, metadata.Description
		}
		d.mu.Unlock()
		if file == nil || r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id": id})
		return
	}

	d.mu.Lock()
	d.nextID++
	id := fmt.Sprintf("id-%d", d.nextID)
	d.files[id] = &fakeFile{id: id, name: metadata.Name, data: data}
	d.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"id": id, "name": metadata.Name})
}

func (d *fakeDrive) handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		d.handleCreate(w, r)
		return
	}
	d.handleList(w, r)
}

func (d *fakeDrive) handleCreate(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.uploadAt = append(d.uploadAt, time.Now())
	d.mu.Unlock()
	if d.shouldFail("upload") {
		if status, body := d.failure("upload"); status != 0 {
			w.WriteHeader(status)
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	var meta struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	d.mu.Lock()
	d.nextID++
	id := fmt.Sprintf("id-%d", d.nextID)
	d.files[id] = &fakeFile{id: id, name: meta.Name, description: meta.Description}
	d.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"id": id, "name": meta.Name})
}

func (d *fakeDrive) handleList(w http.ResponseWriter, r *http.Request) {
	if d.shouldFail("list") {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query().Get("q")
	exact, prefix := parseFakeQuery(query)

	type entry struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	result := struct {
		Files []entry `json:"files"`
	}{}

	d.mu.Lock()
	for _, file := range d.files {
		match := false
		switch {
		case exact != "":
			match = file.name == exact
		case prefix != "":
			match = strings.HasPrefix(file.name, prefix)
		}
		if match {
			result.Files = append(result.Files, entry{
				ID: file.id, Name: file.name, Description: file.description,
			})
		}
	}
	d.mu.Unlock()

	json.NewEncoder(w).Encode(result)
}

func (d *fakeDrive) handleFile(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/files/")

	d.mu.Lock()
	file, ok := d.files[id]
	if ok && r.Method == http.MethodDelete {
		delete(d.files, id)
	}
	var snapshot fakeFile
	if ok {
		// a file can be updated, its fields are read here
		snapshot = *file
	}
	d.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodPatch {
		var meta struct {
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		file.description = meta.Description
		d.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"id": id})
		return
	}
	if strings.Contains(r.URL.RawQuery, "fields=description") {
		json.NewEncoder(w).Encode(map[string]string{"description": snapshot.description})
		return
	}
	w.Write(snapshot.data)
}

func (d *fakeDrive) shouldFail(kind string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failOnce[kind] {
		d.failOnce[kind] = false
		return true
	}
	return false
}

func (d *fakeDrive) failOnceWith(kind string, status int, body string) {
	d.mu.Lock()
	d.failOnce[kind] = true
	d.failStatus[kind] = status
	d.failBody[kind] = body
	d.mu.Unlock()
}

func (d *fakeDrive) failure(kind string) (int, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if status, ok := d.failStatus[kind]; ok {
		return status, d.failBody[kind]
	}
	return 0, ""
}

func (d *fakeDrive) failNext(kind string) {
	d.mu.Lock()
	d.failOnce[kind] = true
	d.mu.Unlock()
}

func (d *fakeDrive) seenHosts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.hosts))
	for h := range d.hosts {
		out = append(out, h)
	}
	return out
}

func (d *fakeDrive) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.files)
}

func parseFakeQuery(query string) (exact, prefix string) {
	if value, ok := cutQuoted(query, "name = '"); ok {
		return value, ""
	}
	if value, ok := cutQuoted(query, "name contains '"); ok {
		return "", value
	}
	return "", ""
}

func cutQuoted(query, marker string) (string, bool) {
	start := strings.Index(query, marker)
	if start < 0 {
		return "", false
	}
	rest := query[start+len(marker):]
	end := strings.Index(rest, "'")
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

func driveSettings() *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			RemoteFolder:      "folder-id",
			Service:           "google-drive",
			Secrets:           []string{"client", "secret", "refresh"},
			FlushIntervalMs:   5,
			PollIntervalMs:    5,
			MaxPollIntervalMs: 20,
			SessionTtlSeconds: 1,
		},
	}
}

func newDriveBackend(t *testing.T) *driveStorage {
	t.Helper()

	storage, err := newDriveStorage(driveSettings(), driveSettings().ProtocolSettings.(*Config))
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	return storage
}

func TestDriveSecrets(t *testing.T) {
	if _, err := newDriveStorage(nil, &Config{RemoteFolder: "f", Secrets: []string{"a", "b"}}); err == nil {
		t.Fatal("accepted two secrets")
	}
	if _, err := newDriveStorage(nil, &Config{Secrets: []string{"a", "b", "c"}}); err == nil {
		t.Fatal("accepted an empty remoteFolder")
	}
	if _, err := newDriveStorage(nil, &Config{RemoteFolder: "f", Secrets: []string{"a", "", "c"}}); err == nil {
		t.Fatal("accepted an empty secret")
	}
}

func TestDriveRoundTrip(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	if err := storage.Put(ctx, "streams/abc/c2s/000000000.seg", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	data, err := storage.Get(ctx, "streams/abc/c2s/000000000.seg")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("Get returned %q, want %q", data, "hello")
	}

	names, err := storage.List(ctx, "streams/abc/c2s")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0].Name != "000000000.seg" {
		t.Fatalf("List returned %v, want 1 segment", names)
	}

	if _, err := storage.Get(ctx, "streams/abc/c2s/000000009.seg"); err != errNotFound {
		t.Fatalf("Get returned %v, want errNotFound", err)
	}

	if err := storage.Delete(ctx, "streams/abc/c2s/000000000.seg"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if drive.count() != 0 {
		t.Fatalf("fake drive still holds %d files", drive.count())
	}
}

func TestDriveListChildren(t *testing.T) {
	newFakeDrive(t)
	storage := newDriveBackend(t)
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

	names, err := storage.List(ctx, "streams")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("List returned %v, want 2 sessions", names)
	}
}

func TestDriveDeleteSession(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	for _, name := range []string{
		"streams/one/c2s/000000000.seg",
		"streams/one/c2s/000000001.end",
		"streams/one/s2c/000000000.seg",
		"streams/two/c2s/000000000.seg",
	} {
		if err := storage.Put(ctx, name, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", name, err)
		}
	}

	if err := storage.Delete(ctx, "streams/one"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if drive.count() != 1 {
		t.Fatalf("fake drive holds %d files, want 1", drive.count())
	}
}

func TestDriveRetry(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	drive.failNext("upload")
	if err := storage.Put(ctx, "sessions/abc", nil); err != nil {
		t.Fatalf("Put did not survive a 429: %v", err)
	}

	drive.failNext("list")
	if _, err := storage.List(ctx, "sessions"); err != nil {
		t.Fatalf("List did not survive a 503: %v", err)
	}
}

func TestDriveTokenCache(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := storage.Put(ctx, fmt.Sprintf("sessions/s%d", i), nil); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if drive.tokens != 1 {
		t.Fatalf("token endpoint hit %d times, want 1", drive.tokens)
	}
}

func TestDriveTransport(t *testing.T) {
	newFakeDrive(t)

	client, server, cleanup := pairWith(t, driveSettings())
	defer cleanup()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")
}

func TestDriveLargeTransfer(t *testing.T) {
	newFakeDrive(t)

	client, server, cleanup := pairWith(t, driveSettings())
	defer cleanup()

	payload := make([]byte, 300000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	go func() {
		client.Write(payload)
	}()

	if err := server.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
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

func TestRateLimited(t *testing.T) {
	limited := []string{
		`{"error":{"code":403,"errors":[{"reason":"userRateLimitExceeded"}]}}`,
		`{"error":{"code":403,"errors":[{"reason":"rateLimitExceeded"}]}}`,
		`{"error":{"code":403,"errors":[{"reason":"sharingRateLimitExceeded"}]}}`,
		`{"error":{"status":"RESOURCE_EXHAUSTED"}}`,
	}
	for _, payload := range limited {
		if !rateLimited([]byte(payload)) {
			t.Fatalf("rateLimited missed %s", payload)
		}
	}

	permanent := []string{
		`{"error":{"code":403,"errors":[{"reason":"insufficientFilePermissions"}]}}`,
		`{"error":{"code":403,"errors":[{"reason":"storageQuotaExceeded"}]}}`,
		`not json at all`,
	}
	for _, payload := range permanent {
		if rateLimited([]byte(payload)) {
			t.Fatalf("rateLimited treated %s as temporary", payload)
		}
	}
}

func TestDriveRetryRateLimit(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)

	drive.failOnceWith("upload", http.StatusForbidden,
		`{"error":{"code":403,"errors":[{"reason":"userRateLimitExceeded"}]}}`)

	if err := storage.Put(context.Background(), "sessions/abc", nil); err != nil {
		t.Fatalf("Put did not survive a 403: %v", err)
	}
}

func TestDriveSharedClient(t *testing.T) {
	newFakeDrive(t)

	first, err := newStorage(driveSettings())
	if err != nil {
		t.Fatalf("newStorage: %v", err)
	}
	second, err := newStorage(driveSettings())
	if err != nil {
		t.Fatalf("newStorage: %v", err)
	}
	if first != second {
		t.Fatal("same settings did not share one storage")
	}
	// a session has an inflight of its own, as large
	session := sessionStorage(first).(*driveStorage)
	defer session.Close()
	if session.inflight == first.(*driveStorage).inflight || cap(session.inflight) != driveMaxInflight {
		t.Fatalf("a session shares inflight or has cap %d", cap(session.inflight))
	}
}

func TestDriveOldServiceName(t *testing.T) {
	newFakeDrive(t)

	settings := driveSettings()
	settings.ProtocolSettings.(*Config).Service = "Google Drive"
	if _, err := newStorage(settings); err != nil {
		t.Fatalf("newStorage: %v", err)
	}
}

func TestDriveInlineListing(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	payload := []byte("small enough to ride along with the listing")
	if err := storage.Put(ctx, "streams/abc/c2s/000000000.seg", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entries, err := storage.List(ctx, "streams/abc/c2s")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %v, want 1 entry", entries)
	}
	if string(entries[0].Inline) != string(payload) {
		t.Fatalf("listing carried %q, want %q", entries[0].Inline, payload)
	}

	d := drive
	d.mu.Lock()
	var stored *fakeFile
	for _, f := range d.files {
		stored = f
	}
	d.mu.Unlock()
	if len(stored.data) != 0 {
		t.Fatal("small payload was uploaded as content")
	}
}

func TestDriveLargeContent(t *testing.T) {
	drive := newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	payload := make([]byte, driveInlineLimit+1)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := storage.Put(ctx, "streams/abc/c2s/000000000.seg", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}

	entries, err := storage.List(ctx, "streams/abc/c2s")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Inline != nil {
		t.Fatalf("large payload was inlined, got %v", entries)
	}

	got, err := storage.Get(ctx, "streams/abc/c2s/000000000.seg")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("Get returned %d bytes, want %d", len(got), len(payload))
	}
	_ = drive
}

func TestDriveInlineGet(t *testing.T) {
	newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()

	payload := []byte("only in the description")
	if err := storage.Put(ctx, "sessions/abc", payload); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := storage.Get(ctx, "sessions/abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}
}

func TestDriveFronting(t *testing.T) {
	drive := newFakeDrive(t)

	fake, err := url.Parse(drive.server.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	port, err := net.PortFromString(fake.Port())
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	driveTokenURL = "http://www.googleapis.com/token"
	driveFilesURL = "http://www.googleapis.com/files"
	driveUploadURL = "http://www.googleapis.com/upload"

	settings := driveSettings()
	settings.Destination = &net.Destination{
		Address: net.ParseAddress(fake.Hostname()),
		Port:    port,
		Network: net.Network_TCP,
	}

	storage, err := newDriveStorage(settings, settings.ProtocolSettings.(*Config))
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}

	if err := storage.Put(context.Background(), "sessions/fronted", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if drive.count() != 1 {
		t.Fatalf("fake drive holds %d files, want 1", drive.count())
	}

	for _, host := range drive.seenHosts() {
		if host != "www.googleapis.com" {
			t.Fatalf("inner host was %q, want www.googleapis.com regardless of address", host)
		}
	}
}

func TestDriveLargeAnnouncement(t *testing.T) {
	listenerCtx, cancelListener := context.WithCancel(context.Background())
	defer cancelListener()
	newFakeDrive(t)
	storage := newDriveBackend(t)
	ctx := context.Background()
	p := paramsFromConfig(driveSettings().ProtocolSettings.(*Config))

	session := "large-announcement"
	r := ring{
		Up:   slotTable{Watermark: "up-watermark"},
		Down: slotTable{Watermark: "down-watermark"},
	}
	for i := range 200 {
		id := fmt.Sprintf("%s-%03d", strings.Repeat("s", 40), i)
		r.Up.Slots = append(r.Up.Slots, id)
		r.Down.Slots = append(r.Down.Slots, id)
	}
	announce, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(announce) <= driveInlineLimit {
		t.Fatalf("announcement is %d bytes, want more than %d", len(announce), driveInlineLimit)
	}
	if err := storage.Put(ctx, announceName(session, time.Now()), announce); err != nil {
		t.Fatal(err)
	}
	entries, err := storage.List(ctx, sessionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Inline != nil {
		t.Fatalf("large announcement was inlined: %v", entries)
	}

	conns := make(chan *Conn, 2)
	l := &Listener{
		ctx:            listenerCtx,
		storage:        storage,
		addConn:        func(c stat.Connection) { conns <- c.(*Conn) },
		params:         p,
		active:         make(map[string]bool),
		handled:        make(map[string]time.Time),
		idleSince:      make(map[string]time.Time),
		announceWarned: make(map[string]bool),
	}
	accepted, err := l.acceptPending(ctx)
	if err != nil || !accepted {
		t.Fatalf("acceptPending: %v, accepted %v", err, accepted)
	}
	conn := <-conns
	reader, ok := conn.reader.(*slotReader)
	if !ok || len(reader.table.Slots) != 200 {
		t.Fatalf("large announcement did not become a 200-slot connection: %T", conn.reader)
	}
	conn.Close()

	empty := "empty-announcement"
	if err := storage.Put(ctx, announceName(empty, time.Now()), nil); err != nil {
		t.Fatal(err)
	}
	accepted, err = l.acceptPending(ctx)
	if err != nil || !accepted {
		t.Fatalf("acceptPending empty: %v, accepted %v", err, accepted)
	}
	conn = <-conns
	if _, ok := conn.reader.(*walReader); !ok {
		t.Fatalf("empty announcement did not become a segment connection: %T", conn.reader)
	}
	conn.Close()
}

func TestDriveDeadCredentials(t *testing.T) {
	drive := newFakeDrive(t)
	drive.mu.Lock()
	drive.tokenStatus = http.StatusBadRequest
	drive.tokenBody = `{"error":"invalid_grant"}`
	drive.mu.Unlock()
	storage := newDriveBackend(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, _, err := storage.do(ctx, http.MethodGet, storage.filesURL, "", nil)
	if !isAuthError(err) {
		t.Fatalf("do returned %v, want the sticky OAuth error", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("do took %v, want it to fail at once", time.Since(start))
	}
	for range 3 {
		if _, err := storage.readDescription(ctx, "id"); !isAuthError(err) {
			t.Fatalf("readDescription returned %v, want the sticky OAuth error", err)
		}
	}
	drive.mu.Lock()
	tokens := drive.tokens
	drive.mu.Unlock()
	if tokens != 1 {
		t.Fatalf("the fake saw %d token requests, want exactly one", tokens)
	}

	reader := newSlotReader(ctx, storage, slotTable{Slots: []string{"id"}, Watermark: "w"}, params{concurrency: 1}, nil)
	select {
	case <-reader.chunks():
	case <-time.After(time.Second):
		t.Fatal("the slot reader kept polling after the credentials were rejected")
	}
	if !isAuthError(reader.Err()) {
		t.Fatalf("the slot reader ended with %v, want the sticky OAuth error", reader.Err())
	}
}

func TestDriveRetryWaitsCooldown(t *testing.T) {
	drive := newFakeDrive(t)
	oldCooldown := driveCooldown
	driveCooldown = 200 * time.Millisecond
	t.Cleanup(func() { driveCooldown = oldCooldown })
	storage := newDriveBackend(t)

	drive.failOnceWith("upload", http.StatusForbidden,
		`{"error":{"code":403,"errors":[{"reason":"userRateLimitExceeded"}]}}`)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := storage.Put(ctx, "sessions/abc", nil); err != nil {
		t.Fatalf("Put did not survive a 403: %v", err)
	}
	drive.mu.Lock()
	times := append([]time.Time(nil), drive.uploadAt...)
	drive.mu.Unlock()
	if len(times) < 2 {
		t.Fatalf("the fake saw %d writes, want a retry", len(times))
	}
	if gap := times[1].Sub(times[0]); gap < driveCooldown/2 {
		t.Fatalf("the retry arrived after %v, less than the jitter floor %v", gap, driveCooldown/2)
	}
	storage.coolMu.Lock()
	until := storage.coolUntil
	storage.coolMu.Unlock()
	if times[1].Before(until) {
		t.Fatalf("the retry reached the fake at %v, before the cooldown ended at %v", times[1], until)
	}
	if took := time.Since(start); took < until.Sub(times[0]) {
		t.Fatalf("the request took %v, less than the cooldown %v", took, until.Sub(times[0]))
	}
}

func TestDriveBackgroundTokenRefresh(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	mode := "ok"
	delay := 100 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		current := mode
		pause := delay
		mu.Unlock()
		time.Sleep(pause)
		switch current {
		case "transient":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		case "auth":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": fmt.Sprintf("token-%d", n),
				"expires_in":   100,
			})
		}
	}))
	defer server.Close()

	newStorage := func() *driveStorage {
		return &driveStorage{driveShared: &driveShared{
			tokenClient: server.Client(),
			tokenURL:    server.URL,
		}}
	}
	seed := func(s *driveStorage) {
		s.tokenMu.Lock()
		s.token = "old"
		s.tokenLifetime = 100 * time.Second
		s.tokenExpiry = time.Now().Add(10 * time.Second)
		s.tokenMu.Unlock()
	}
	setMode := func(m string) {
		mu.Lock()
		mode = m
		mu.Unlock()
	}
	callCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	t.Run("returns at once inside the window", func(t *testing.T) {
		s := newStorage()
		seed(s)
		start := time.Now()
		token, err := s.accessToken(context.Background())
		if err != nil || token != "old" {
			t.Fatalf("accessToken gave %q, %v", token, err)
		}
		if time.Since(start) > 50*time.Millisecond {
			t.Fatalf("accessToken waited %v for the background refresh", time.Since(start))
		}
		waitFor(t, "the background refresh", func() bool {
			s.tokenMu.Lock()
			defer s.tokenMu.Unlock()
			return s.token != "old" && !s.refreshing
		})
	})

	t.Run("concurrent calls start one refresh", func(t *testing.T) {
		mu.Lock()
		calls = 0
		mu.Unlock()
		s := newStorage()
		seed(s)
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if token, err := s.accessToken(context.Background()); err != nil || token != "old" {
					t.Errorf("accessToken gave %q, %v", token, err)
				}
			}()
		}
		wg.Wait()
		waitFor(t, "one background refresh", func() bool {
			s.tokenMu.Lock()
			defer s.tokenMu.Unlock()
			return !s.refreshing && s.token != "old"
		})
		if n := callCount(); n != 1 {
			t.Fatalf("concurrent calls started %d refreshes, want one", n)
		}
	})

	t.Run("transient failure keeps the old token", func(t *testing.T) {
		mu.Lock()
		calls = 0
		mu.Unlock()
		setMode("transient")
		defer setMode("ok")
		s := newStorage()
		seed(s)
		if token, err := s.accessToken(context.Background()); err != nil || token != "old" {
			t.Fatalf("accessToken gave %q, %v", token, err)
		}
		waitFor(t, "the failed refresh to clear", func() bool {
			s.tokenMu.Lock()
			defer s.tokenMu.Unlock()
			return !s.refreshing
		})
		s.tokenMu.Lock()
		token := s.token
		s.tokenMu.Unlock()
		if token != "old" {
			t.Fatalf("a transient failure replaced the token with %q", token)
		}
		// Simulate the backoff having elapsed so the next call may retry.
		s.tokenMu.Lock()
		s.tokenRetryAt = time.Time{}
		s.tokenBackoff = 0
		s.tokenMu.Unlock()
		setMode("ok")
		if _, err := s.accessToken(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the later refresh", func() bool {
			s.tokenMu.Lock()
			defer s.tokenMu.Unlock()
			return s.token != "old" && !s.refreshing
		})
		if n := callCount(); n != 2 {
			t.Fatalf("the retry made %d token requests, want two", n)
		}
	})

	t.Run("auth failure turns sticky", func(t *testing.T) {
		mu.Lock()
		calls = 0
		mu.Unlock()
		setMode("auth")
		defer setMode("ok")
		s := newStorage()
		seed(s)
		if _, err := s.accessToken(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the sticky auth error", func() bool {
			s.tokenMu.Lock()
			defer s.tokenMu.Unlock()
			return s.authErr != nil && !s.refreshing
		})
		before := callCount()
		if _, err := s.accessToken(context.Background()); !isAuthError(err) {
			t.Fatalf("accessToken gave %v, want the sticky auth error", err)
		}
		if n := callCount(); n != before {
			t.Fatalf("the sticky error made %d more token requests", n-before)
		}
	})
}

func TestSlotPathDefaults(t *testing.T) {
	p := paramsForStorage(&Config{}, &driveStorage{})
	if p.concurrency != 64 || p.flushInterval != 10*time.Millisecond || p.maxPollInterval != 200*time.Millisecond {
		t.Fatalf("slot defaults gave concurrency %d, flush %v, max poll %v", p.concurrency, p.flushInterval, p.maxPollInterval)
	}
	if wal, base := paramsForStorage(&Config{}, &localStorage{}), paramsFromConfig(&Config{}); wal != base {
		t.Fatalf("wal defaults changed: %+v, want %+v", wal, base)
	}
	explicit := paramsForStorage(&Config{Concurrency: 4, FlushIntervalMs: 30, MaxPollIntervalMs: 100}, &driveStorage{})
	if explicit.concurrency != 4 || explicit.flushInterval != 30*time.Millisecond || explicit.maxPollInterval != 100*time.Millisecond {
		t.Fatalf("explicit values did not win: %+v", explicit)
	}
	if p := paramsForStorage(&Config{PollIntervalMs: 500}, &driveStorage{}); p.maxPollInterval < p.minPollInterval {
		t.Fatalf("max poll %v is below min poll %v", p.maxPollInterval, p.minPollInterval)
	}
}

func TestDialDefaultRingDepth(t *testing.T) {
	newFakeDrive(t)
	config := &Config{
		RemoteFolder: "folder-id",
		Service:      "google-drive",
		Secrets:      []string{"client", "secret", "refresh"},
	}
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: config,
	}
	conn, err := Dial(context.Background(), net.Destination{}, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writer, ok := conn.(*Conn).writer.(*slotWriter)
	if !ok {
		t.Fatalf("Dial with unset concurrency built %T, want a slot writer", conn.(*Conn).writer)
	}
	if len(writer.table.Slots) != 64 {
		t.Fatalf("Dial with unset concurrency built %d slots, want 64", len(writer.table.Slots))
	}
	box := spareBoxFor(config)
	box.stop.Store(true)
	for box.busy.Load() {
		time.Sleep(10 * time.Millisecond)
	}
}
