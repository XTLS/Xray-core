package xdrive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecodeRingCaps(t *testing.T) {
	good := ring{
		Up:   slotTable{Slots: []string{"a", "b"}, Watermark: "w"},
		Down: slotTable{Slots: []string{"c", "d"}, Watermark: "w"},
	}
	b, _ := json.Marshal(good)
	if _, ok := decodeRing(b); !ok {
		t.Fatal("a normal ring was rejected")
	}

	tooMany := good
	tooMany.Up.Slots = make([]string, maxConcurrency+1)
	for i := range tooMany.Up.Slots {
		tooMany.Up.Slots[i] = "s"
	}
	b, _ = json.Marshal(tooMany)
	if _, ok := decodeRing(b); ok {
		t.Fatalf("a ring with %d slots per table was accepted", maxConcurrency+1)
	}

	longID := good
	longID.Up.Slots[0] = strings.Repeat("x", maxSlotIDLen+1)
	b, _ = json.Marshal(longID)
	if _, ok := decodeRing(b); ok {
		t.Fatal("a ring with an over-long slot id was accepted")
	}

	longWM := good
	longWM.Down.Watermark = strings.Repeat("w", maxSlotIDLen+1)
	b, _ = json.Marshal(longWM)
	if _, ok := decodeRing(b); ok {
		t.Fatal("a ring with an over-long watermark id was accepted")
	}

	emptyID := good
	emptyID.Down.Slots[1] = ""
	b, _ = json.Marshal(emptyID)
	if _, ok := decodeRing(b); ok {
		t.Fatal("a ring with an empty slot id was accepted")
	}
}

func capTestStorage(t *testing.T, body []byte) (*driveStorage, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return &driveStorage{
		driveShared: &driveShared{token: "t", tokenExpiry: time.Now().Add(time.Hour)},
		client:      srv.Client(),
		inflight:    make(chan struct{}, 1),
		reserved:    make(chan struct{}, 1),
	}, srv.URL
}

func TestDriveResponseBodyCap(t *testing.T) {
	old := driveMaxResponse
	driveMaxResponse = 16
	t.Cleanup(func() { driveMaxResponse = old })
	s, url := capTestStorage(t, make([]byte, 32))
	_, _, err := s.do(context.Background(), http.MethodGet, url, "", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an over-cap body returned %v, want a cap error", err)
	}
}

func TestDriveAnnouncementBodyCap(t *testing.T) {
	s, url := capTestStorage(t, make([]byte, 32))
	ctx := context.WithValue(context.Background(), maxBodyKey{}, int64(8))
	_, _, err := s.do(ctx, http.MethodGet, url, "", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an over-cap announcement returned %v, want a cap error", err)
	}
}

func TestDriveNormal16MiBSegment(t *testing.T) {
	body := make([]byte, 16<<20)
	s, url := capTestStorage(t, body)
	_, payload, err := s.do(context.Background(), http.MethodGet, url, "", nil)
	if err != nil {
		t.Fatalf("a normal 16 MiB segment failed: %v", err)
	}
	if len(payload) != len(body) {
		t.Fatalf("read %d bytes, want %d", len(payload), len(body))
	}
}
