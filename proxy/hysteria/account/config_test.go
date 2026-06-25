package account

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestValidatorGetAcceptsVlessRouteAuthVariant(t *testing.T) {
	const serverAuth = "00000000-0000-1234-8000-000000000000"
	const clientAuth = "00000000-0000-0001-8000-000000000000"

	user := &protocol.MemoryUser{
		Email:   "user@example.com",
		Level:   1,
		Account: &MemoryAccount{Auth: serverAuth},
	}
	validator := NewValidator()
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}

	got := validator.Get(clientAuth)
	if got == nil {
		t.Fatal("validator did not accept UUID auth variant with a different VLESS route")
	}
	if got == user {
		t.Fatal("validator returned stored user instead of a copy with the client auth")
	}
	if got.Email != user.Email || got.Level != user.Level {
		t.Fatalf("validator returned wrong user metadata: %v", got)
	}
	if got.Account.(*MemoryAccount).Auth != clientAuth {
		t.Fatalf("returned auth = %q, want %q", got.Account.(*MemoryAccount).Auth, clientAuth)
	}
	if user.Account.(*MemoryAccount).Auth != serverAuth {
		t.Fatalf("stored auth was mutated to %q", user.Account.(*MemoryAccount).Auth)
	}
	if got := validator.Get("00000000-0000-0001-9000-000000000000"); got != nil {
		t.Fatalf("validator accepted auth with non-route bytes changed: %v", got)
	}
	if got := validator.Get("password"); got != nil {
		t.Fatalf("validator accepted unrelated password auth: %v", got)
	}
}
