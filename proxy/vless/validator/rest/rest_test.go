package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

type capturingLogHandler struct {
	mu   sync.Mutex
	msgs []log.Message
}

func (h *capturingLogHandler) Handle(msg log.Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, msg)
}

func (h *capturingLogHandler) contains(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if strings.Contains(m.String(), substr) {
			return true
		}
	}
	return false
}

func newTestValidatorAgainstServer(t *testing.T, handler http.HandlerFunc) (*Validator, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	v, err := NewValidator(&Config{Address: srv.URL})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v, srv
}

func newVlessUser(t *testing.T, email string) *protocol.MemoryUser {
	t.Helper()
	return &protocol.MemoryUser{
		Email: email,
		Level: 3,
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(uuid.New()),
		},
	}
}

func TestValidatorAdd2xx(t *testing.T) {
	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{}})
	})
	if err := v.Add(newVlessUser(t, "a@example.com")); err != nil {
		t.Fatalf("Add: %v", err)
	}
}

func TestValidatorAdd409Conflict(t *testing.T) {
	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	err := v.Add(newVlessUser(t, "a@example.com"))
	if err == nil {
		t.Fatal("expected error on 409")
	}
}

func TestValidatorAdd5xxLogsAndErrors(t *testing.T) {
	orig := &captureOriginal{}
	handler := &capturingLogHandler{}
	orig.set(handler)
	defer orig.restore()

	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"title":"boom"}`))
	})
	err := v.Add(newVlessUser(t, "a@example.com"))
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !handler.contains("REST validator") {
		t.Fatal("expected 5xx failure to be logged, found nothing matching")
	}
}

func TestValidatorGet404IsNilNotError(t *testing.T) {
	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if u := v.Get(uuid.New()); u != nil {
		t.Fatalf("expected nil user on 404, got %+v", u)
	}
}

func TestValidatorGet5xxLogs(t *testing.T) {
	orig := &captureOriginal{}
	handler := &capturingLogHandler{}
	orig.set(handler)
	defer orig.restore()

	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if u := v.Get(uuid.New()); u != nil {
		t.Fatalf("expected nil user on 502, got %+v", u)
	}
	if !handler.contains("REST validator") {
		t.Fatal("expected 5xx failure to be logged on Get, found nothing matching")
	}
}

func TestValidatorGetByEmail2xx(t *testing.T) {
	email := "user@example.com"
	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		id := uuid.New()
		json.NewEncoder(w).Encode(map[string]any{
			"email":   email,
			"account": map[string]any{"id": id.String()},
		})
	})
	u := v.GetByEmail(email)
	if u == nil || u.Email != email {
		t.Fatalf("GetByEmail returned %+v", u)
	}
}

func TestValidatorGetCount(t *testing.T) {
	v, _ := newTestValidatorAgainstServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"count": 7})
	})
	if n := v.GetCount(); n != 7 {
		t.Fatalf("GetCount = %d, want 7", n)
	}
}

func TestMemoryUserRESTRoundTrip(t *testing.T) {
	orig := newVlessUser(t, "roundtrip@example.com")

	restUser, err := memoryUserToREST(orig)
	if err != nil {
		t.Fatalf("memoryUserToREST: %v", err)
	}
	if restUser.Email == nil || *restUser.Email != orig.Email {
		t.Fatalf("email mismatch: %+v", restUser)
	}

	back, err := restUserToMemory(restUser)
	if err != nil {
		t.Fatalf("restUserToMemory: %v", err)
	}
	if back.Email != orig.Email {
		t.Fatalf("email mismatch after round trip: got %q want %q", back.Email, orig.Email)
	}
	if back.Level != orig.Level {
		t.Fatalf("level mismatch after round trip: got %d want %d", back.Level, orig.Level)
	}
	origID := orig.Account.(*vless.MemoryAccount).ID.UUID()
	backID := back.Account.(*vless.MemoryAccount).ID.UUID()
	if origID != backID {
		t.Fatalf("id mismatch after round trip: got %v want %v", backID, origID)
	}
}

// captureOriginal swaps the process-wide log handler for the duration of a
// test and restores it afterwards. common/log has no getter, so tests that
// need to assert on log output install their own handler and restore a
// no-op one when done.
type captureOriginal struct{}

func (captureOriginal) set(h log.Handler) { log.RegisterHandler(h) }
func (captureOriginal) restore()          { log.RegisterHandler(noopLogHandler{}) }

type noopLogHandler struct{}

func (noopLogHandler) Handle(log.Message) {}
