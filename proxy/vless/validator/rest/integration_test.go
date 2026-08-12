//go:build integration

// Integration test for the REST validator against a real process running
// proxy/vless/validator/rest/test_serv. Run with:
//
//	go test -tags integration ./proxy/vless/validator/rest/...
//
// Manual procedure (if `go run` is unavailable in the environment):
//  1. go build -o rest-test-server ./proxy/vless/validator/rest/test_serv
//  2. ./rest-test-server -listen :8080
//  3. Point a "rest" validator at http://127.0.0.1:8080 and exercise
//     Add/Get/GetByEmail/Del through it, e.g. via a VLESS inbound config.
package rest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func startTestServ(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "go", "run", "./test_serv", "-listen", addr)
	cmd.Dir = "."
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start test_serv: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
	})

	baseURL := "http://" + addr
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return baseURL
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("test_serv did not become healthy in time")
	return ""
}

func TestIntegrationRESTValidatorRoundTrip(t *testing.T) {
	baseURL := startTestServ(t)

	v, err := NewValidator(&Config{Address: baseURL})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	email := fmt.Sprintf("integration-%d@example.com", time.Now().UnixNano())
	user := &protocol.MemoryUser{
		Email: email,
		Level: 1,
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(uuid.New()),
		},
	}

	if err := v.Add(user); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := v.Add(user); err == nil {
		t.Fatal("expected error re-adding same email")
	}

	got := v.GetByEmail(email)
	if got == nil || got.Email != email {
		t.Fatalf("GetByEmail returned %+v", got)
	}

	id := user.Account.(*vless.MemoryAccount).ID.UUID()
	byID := v.Get(id)
	if byID == nil || byID.Email != email {
		t.Fatalf("Get returned %+v", byID)
	}

	if err := v.Del(email); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if u := v.GetByEmail(email); u != nil {
		t.Fatalf("expected nil after Del, got %+v", u)
	}
	if err := v.Del(email); err == nil {
		t.Fatal("expected error deleting already-deleted user")
	}
}
