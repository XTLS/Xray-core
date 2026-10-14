package account_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestValidatorRemoveEndsDerivedUser(t *testing.T) {
	v := account.NewValidator()
	a, err := (&account.Account{Auth: "27e2bd8b-8ad6-4d2a-b3cf-1a8a3a0fe2b1"}).AsAccount()
	common.Must(err)
	u := &protocol.MemoryUser{Email: "a@test", Account: a}
	common.Must(v.Add(u))

	// The same UUID with other route bytes (its 7th and 8th bytes) gets a
	// derived copy of the user.
	d := v.Get("27e2bd8b-8ad6-ffff-b3cf-1a8a3a0fe2b1")
	if d == nil || d == u {
		t.Fatal("expected a derived user")
	}
	common.Must(v.DelByEmail("a@test"))
	if d.Context().Err() == nil {
		t.Fatal("derived user's context is not done after removal")
	}
}
