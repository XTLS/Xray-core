package account

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestValidatorGetAcceptsHysteriaRouteAuthVariant(t *testing.T) {
	user := &protocol.MemoryUser{
		Email:   "user@example.com",
		Account: &MemoryAccount{Auth: "00000000-0000-1234-8000-000000000000"},
	}
	validator := NewValidator()
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}

	if got := validator.Get("00000000-0000-0001-8000-000000000000"); got != user {
		t.Fatal("validator did not accept UUID auth variant with a different Hysteria route")
	}
	if got := validator.Get("00000000-0000-0001-9000-000000000000"); got != nil {
		t.Fatalf("validator accepted auth with non-route bytes changed: %v", got)
	}
	if got := validator.Get("password"); got != nil {
		t.Fatalf("validator accepted unrelated password auth: %v", got)
	}
}
