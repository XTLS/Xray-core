package vless_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	. "github.com/xtls/xray-core/proxy/vless"
)

func TestExternalValidator(t *testing.T) {
	valid := uuid.New()
	staticID := uuid.New()
	var hits int32
	shortLived := uuid.New()
	limited := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.URL.Query().Get("uuid") {
		case valid.String():
			w.Write([]byte(`{"email":"a@b.c","level":1,"flow":""}`))
		case shortLived.String():
			w.Write([]byte(`{"email":"s@b.c","ttl":1}`))
		case limited.String():
			if r.URL.Query().Get("ip") != "1.1.1.1" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"email":"l@b.c"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	base := new(MemoryValidator)
	common.Must(base.Add(&protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(staticID)},
		Email:   "static@example.com",
	}))

	v, err := NewExternalValidator(context.Background(), nil, base, ExternalValidatorConfig{
		URL:         srv.URL,
		CacheTTL:    60 * time.Second,
		NegativeTTL: 60 * time.Second,
	})
	common.Must(err)
	defer v.Close()

	if u := v.Get(staticID); u == nil || u.Email != "static@example.com" {
		t.Fatal("static user not resolved locally")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("static user lookup hit the backend")
	}

	if u := v.Get(valid); u == nil || u.Email != "a@b.c" || u.Level != 1 {
		t.Fatal("external user not resolved")
	}
	if u := v.Get(valid); u == nil {
		t.Fatal("cached user not resolved")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatal("expected 1 backend hit, got ", got)
	}

	unknown := uuid.New()
	if u := v.Get(unknown); u != nil {
		t.Fatal("unknown user resolved")
	}
	if u := v.Get(unknown); u != nil {
		t.Fatal("unknown user resolved from cache")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatal("negative result not cached, backend hits: ", got)
	}

	if u := v.Get(shortLived); u == nil || u.Email != "s@b.c" {
		t.Fatal("short-lived user not resolved")
	}
	if u := v.Get(shortLived); u == nil {
		t.Fatal("short-lived user not cached")
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatal("server ttl not cached, backend hits: ", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if u := v.Get(shortLived); u == nil {
		t.Fatal("short-lived user not re-resolved")
	}
	if got := atomic.LoadInt32(&hits); got != 4 {
		t.Fatal("server ttl not honored, backend hits: ", got)
	}

	dev1 := v.WithSource(net.TCPDestination(net.ParseAddress("1.1.1.1"), 443))
	dev2 := v.WithSource(net.TCPDestination(net.ParseAddress("2.2.2.2"), 443))
	if u := dev1.Get(limited); u == nil || u.Email != "l@b.c" {
		t.Fatal("allowed source ip not resolved")
	}
	if u := dev2.Get(limited); u != nil {
		t.Fatal("denied source ip resolved")
	}
	dev1.Get(limited)
	dev2.Get(limited)
	if got := atomic.LoadInt32(&hits); got != 6 {
		t.Fatal("per-ip results not cached separately, backend hits: ", got)
	}

	common.Must(v.Del(limited.String()))
	if u := dev1.Get(limited); u == nil {
		t.Fatal("user not re-resolved after eviction by uuid")
	}
	if got := atomic.LoadInt32(&hits); got != 7 {
		t.Fatal("eviction by uuid did not drop cache entries, backend hits: ", got)
	}

	common.Must(v.Del("a@b.c"))
	if u := v.Get(valid); u == nil {
		t.Fatal("user not re-resolved after eviction by email")
	}
	if got := atomic.LoadInt32(&hits); got != 8 {
		t.Fatal("eviction by email did not drop cache entries, backend hits: ", got)
	}

	if err := v.Del(unknown.String()); err == nil {
		t.Fatal("expected error deleting a uuid that was only ever negatively cached")
	}

	if err := v.Del("nobody@example.com"); err == nil {
		t.Fatal("expected error for unknown email")
	}
	common.Must(v.Del("static@example.com"))
	if u := base.Get(staticID); u != nil {
		t.Fatal("static user not removed from base validator")
	}
}

func TestExternalValidatorHeaders(t *testing.T) {
	id := uuid.New()
	var gotAuth, gotMeta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMeta = r.Header.Get("X-Node-Region")
		if gotAuth != "Bearer s3cr3t" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"email":"tok@b.c"}`))
	}))
	defer srv.Close()

	v, err := NewExternalValidator(context.Background(), nil, new(MemoryValidator), ExternalValidatorConfig{
		URL: srv.URL,
		Headers: map[string]string{
			"Authorization": "Bearer s3cr3t",
			"X-Node-Region": "fra",
		},
	})
	common.Must(err)
	defer v.Close()

	if u := v.Get(id); u == nil || u.Email != "tok@b.c" {
		t.Fatal("user not resolved with configured headers")
	}
	if gotAuth != "Bearer s3cr3t" || gotMeta != "fra" {
		t.Fatal("headers not sent as expected, got Authorization=", gotAuth, " X-Node-Region=", gotMeta)
	}
}

func TestExternalValidatorFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	v, err := NewExternalValidator(context.Background(), nil, new(MemoryValidator), ExternalValidatorConfig{
		URL:     srv.URL,
		Timeout: 50 * time.Millisecond,
	})
	common.Must(err)
	defer v.Close()

	start := time.Now()
	if u := v.Get(uuid.New()); u != nil {
		t.Fatal("expected nil on backend timeout")
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("lookup timeout not enforced")
	}
}

func TestExternalValidatorBadConfig(t *testing.T) {
	base := new(MemoryValidator)
	for _, url := range []string{"ftp://example.com", "not a url"} {
		if _, err := NewExternalValidator(context.Background(), nil, base, ExternalValidatorConfig{URL: url}); err == nil {
			t.Fatal("expected error for ", url)
		}
	}
}
