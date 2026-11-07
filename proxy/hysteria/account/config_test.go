package account_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/hysteria/account"
)

func newUser(email, auth string) *protocol.MemoryUser {
	a, err := (&Account{Auth: auth}).AsAccount()
	common.Must(err)
	return &protocol.MemoryUser{Email: email, Account: a}
}

func TestValidatorRejectsDuplicateEmail(t *testing.T) {
	v := NewValidator()
	common.Must(v.Add(newUser("love@example.com", "old-password")))

	if err := v.Add(newUser("Love@example.com", "new-password")); err == nil {
		t.Fatal("expected an error when adding a second user with the same email")
	}
	if c := v.GetCount(); c != 1 {
		t.Fatalf("expected 1 user, got %d", c)
	}

	common.Must(v.DelByEmail("love@example.com"))
	if u := v.Get("old-password"); u != nil {
		t.Fatal("removed user can still authenticate")
	}
	if u := v.Get("new-password"); u != nil {
		t.Fatal("rejected user can authenticate")
	}
	if c := v.GetCount(); c != 0 {
		t.Fatalf("expected 0 users, got %d", c)
	}
}

func TestValidatorDelByEmail(t *testing.T) {
	v := NewValidator()
	common.Must(v.Add(newUser("love@example.com", "b831381d-6324-4d53-ad4f-8cda48b30811")))

	if err := v.DelByEmail("unknown@example.com"); err == nil {
		t.Fatal("expected an error when removing an unknown user")
	}
	if err := v.DelByEmail(""); err == nil {
		t.Fatal("expected an error when removing an empty email")
	}

	common.Must(v.DelByEmail("LOVE@example.com"))
	if u := v.Get("b831381d-6324-4d53-ad4f-8cda48b30811"); u != nil {
		t.Fatal("removed user can still authenticate")
	}
	if err := v.DelByEmail("love@example.com"); err == nil {
		t.Fatal("expected an error when removing the same user twice")
	}
}
