package socks

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/http"
)

// What the API checks before it will touch an inbound: without this the gRPC
// call fails with "proxy is not a UserManager".
var (
	_ proxy.UserManager = (*Server)(nil)
	_ proxy.UserManager = (*http.Server)(nil)
)

func socksUser(username, password string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account: &Account{Username: username, Password: password},
	}
}

// A server built by hand: NewServer needs a core instance in the context, and
// none of this touches the parts that need one.
func testServer(auth AuthType, accounts map[string]string) *Server {
	return &Server{
		config:    &ServerConfig{AuthType: auth, Accounts: accounts},
		validator: http.NewAccountValidator(accounts),
	}
}

func TestAddUserOnPasswordInbound(t *testing.T) {
	s := testServer(AuthType_PASSWORD, map[string]string{"alice": "pw1"})
	ctx := context.Background()

	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount() = %d, want 1", got)
	}
	if err := s.AddUser(ctx, socksUser("bob", "pw2")); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if got := s.GetUsersCount(ctx); got != 2 {
		t.Errorf("GetUsersCount() = %d after adding one, want 2", got)
	}
	if u := s.GetUser(ctx, "bob"); u == nil {
		t.Error("GetUser did not find the account that was just added")
	}
	if got := len(s.GetUsers(ctx)); got != 2 {
		t.Errorf("GetUsers returned %d users, want 2", got)
	}

	// The account is what the SOCKS handshake will check.
	if !s.validator.Has("bob", "pw2") {
		t.Error("account added over the API is not accepted by the validator")
	}

	if err := s.RemoveUser(ctx, "bob"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if s.validator.Has("bob", "pw2") {
		t.Error("removed account is still accepted")
	}
	if err := s.RemoveUser(ctx, "bob"); err == nil {
		t.Error("removing the same user twice reported success")
	}
}

// An inbound that does not ask for a password never checks its accounts, so
// adding one would be silently ineffective on the SOCKS side.
func TestAddUserRefusedWithoutPasswordAuth(t *testing.T) {
	s := testServer(AuthType_NO_AUTH, nil)

	if err := s.AddUser(context.Background(), socksUser("alice", "pw1")); err == nil {
		t.Error("AddUser on a no-auth inbound reported success")
	}
	if got := s.GetUsersCount(context.Background()); got != 0 {
		t.Errorf("GetUsersCount() = %d, want 0", got)
	}
}

// The HTTP half of the inbound has to see the same accounts: since #3682 one
// SOCKS inbound serves both protocols.
func TestAddUserSharedWithHTTPHalf(t *testing.T) {
	s := testServer(AuthType_PASSWORD, map[string]string{"alice": "pw1"})
	httpServer := &httpServerStub{validator: s.validator}

	if err := s.AddUser(context.Background(), socksUser("bob", "pw2")); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if !httpServer.validator.Has("bob", "pw2") {
		t.Error("the HTTP half does not see the account added through SOCKS")
	}
}

type httpServerStub struct {
	validator *http.AccountValidator
}
