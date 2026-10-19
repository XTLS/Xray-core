package http_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/http"
)

func user(username, password, email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account: &http.Account{Username: username, Password: password},
		Email:   email,
	}
}

func TestValidatorFromConfig(t *testing.T) {
	v := http.NewAccountValidator(map[string]string{"alice": "pw1", "bob": "pw2"})

	if v.Empty() {
		t.Fatal("validator built from two accounts reports empty")
	}
	if got := v.Count(); got != 2 {
		t.Fatalf("Count() = %d, want 2", got)
	}
	if !v.Has("alice", "pw1") {
		t.Error("account from config is not accepted")
	}
	if v.Has("alice", "pw2") {
		t.Error("wrong password is accepted")
	}
	if v.Has("carol", "pw1") {
		t.Error("unknown user is accepted")
	}
}

func TestValidatorNilConfig(t *testing.T) {
	v := http.NewAccountValidator(nil)

	if !v.Empty() {
		t.Error("validator with no accounts does not report empty")
	}
	if v.Has("alice", "pw1") {
		t.Error("empty validator accepts an account")
	}
}

func TestValidatorAdd(t *testing.T) {
	v := http.NewAccountValidator(nil)

	if err := v.Add(user("alice", "pw1", "alice@example.com")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !v.Has("alice", "pw1") {
		t.Error("account added at runtime is not accepted")
	}
	if v.Empty() {
		t.Error("validator reports empty after an account was added")
	}

	if err := v.Add(user("alice", "pw2", "")); err == nil {
		t.Error("adding a duplicate username was allowed")
	}
	if !v.Has("alice", "pw1") {
		t.Error("rejected duplicate overwrote the existing account")
	}

	if err := v.Add(user("", "pw", "")); err == nil {
		t.Error("account without a username was allowed")
	}
	if err := v.Add(&protocol.MemoryUser{}); err == nil {
		t.Error("user without an account was allowed")
	}
	if err := v.Add(nil); err == nil {
		t.Error("nil user was allowed")
	}
}

func TestValidatorAddFillsEmail(t *testing.T) {
	v := http.NewAccountValidator(nil)
	u := user("alice", "pw1", "")
	if err := v.Add(u); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if u.Email != "alice" {
		t.Errorf("Email = %q, want the username when none was given", u.Email)
	}
}

func TestValidatorDel(t *testing.T) {
	v := http.NewAccountValidator(nil)
	if err := v.Add(user("alice", "pw1", "alice@example.com")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := v.Add(user("bob", "pw2", "")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// by e-mail, the key the API uses
	if err := v.Del("alice@example.com"); err != nil {
		t.Fatalf("Del by e-mail: %v", err)
	}
	if v.Has("alice", "pw1") {
		t.Error("deleted account is still accepted")
	}

	// by username, the key an operator has at hand
	if err := v.Del("BOB"); err != nil {
		t.Fatalf("Del by username, case-insensitive: %v", err)
	}
	if !v.Empty() {
		t.Error("validator is not empty after both accounts were deleted")
	}

	if err := v.Del("nobody"); err == nil {
		t.Error("deleting an unknown user reported success")
	}
	if err := v.Del(""); err == nil {
		t.Error("deleting an empty key reported success")
	}
}

func TestValidatorGet(t *testing.T) {
	v := http.NewAccountValidator(nil)
	if err := v.Add(user("alice", "pw1", "alice@example.com")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if got := v.Get("alice@example.com"); got == nil {
		t.Error("Get by e-mail returned nil")
	}
	if got := v.Get("alice"); got == nil {
		t.Error("Get by username returned nil")
	}
	if got := v.Get("nobody"); got != nil {
		t.Error("Get returned a user for an unknown key")
	}
	if got := v.Get(""); got != nil {
		t.Error("Get returned a user for an empty key")
	}
}

func TestValidatorGetAllIsACopy(t *testing.T) {
	v := http.NewAccountValidator(map[string]string{"alice": "pw1"})

	all := v.GetAll()
	if len(all) != 1 {
		t.Fatalf("GetAll returned %d users, want 1", len(all))
	}
	all[0] = nil
	if again := v.GetAll(); len(again) != 1 || again[0] == nil {
		t.Error("writing to the returned slice changed the validator")
	}
}

// The handshake reads accounts while the API writes them. Run with -race.
func TestValidatorConcurrent(t *testing.T) {
	v := http.NewAccountValidator(map[string]string{"alice": "pw1"})
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			v.Has("alice", "pw1")
			v.Count()
			v.GetAll()
		}
	}()
	for i := 0; i < 500; i++ {
		_ = v.Add(user("bob", "pw2", ""))
		_ = v.Del("bob")
	}
	<-done

	if !v.Has("alice", "pw1") {
		t.Error("the account from the config did not survive the churn")
	}
}
