package vmess_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	. "github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

func toAccount(a *Account) protocol.Account {
	account, err := a.AsAccount()
	common.Must(err)
	return account
}

func TestUserRouteIdentityLifecycle(t *testing.T) {
	const id = "317530a8-3c1d-1234-8d8e-7cb70aedf158"
	const variant = "317530a8-3c1d-ffff-8d8e-7cb70aedf158"
	account := toAccount(&Account{Id: id, UserRoute: true}).(*MemoryAccount)
	other := toAccount(&Account{Id: variant, UserRoute: true}).(*MemoryAccount)
	legacy := toAccount(&Account{Id: id}).(*MemoryAccount)
	if !account.Equals(other) || account.Equals(legacy) || legacy.Equals(account) || !bytes.Equal(account.CmdKey(), other.CmdKey()) {
		t.Fatal("incorrect route identity")
	}
	if !bytes.Equal(legacy.CmdKey(), legacy.ID.CmdKey()) {
		t.Fatal("standard VMess key changed")
	}
	if account.ID.String() != id {
		t.Fatal("key derivation mutated the configured UUID")
	}
	roundTrip := account.ToProto().(*Account)
	if roundTrip.Id != id || !roundTrip.UserRoute || !account.Equals(toAccount(roundTrip)) {
		t.Fatal("account round trip lost route mode")
	}
	validator := NewTimedUserValidator()
	user := &protocol.MemoryUser{Email: "first", Account: account}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(&protocol.MemoryUser{Email: "duplicate", Account: other}); err == nil {
		t.Fatal("ambiguous route identity accepted")
	}
	if validator.GetCount() != 1 {
		t.Fatal("failed add changed user count")
	}
	// The same full UUID may coexist in standard mode, with independent keys.
	if err := validator.Add(&protocol.MemoryUser{Email: "legacy", Account: legacy}); err != nil {
		t.Fatal(err)
	}
	authID := aead.CreateAuthID(other.CmdKey(), time.Now().Unix())
	got, found, err := validator.GetAEAD(authID[:])
	if err != nil || !found || got != user {
		t.Fatalf("route variant authenticated as %v: %v", got, err)
	}
	if !validator.Remove("FIRST") {
		t.Fatal("failed to remove route identity")
	}
	authID = aead.CreateAuthID(other.CmdKey(), time.Now().Unix())
	if _, found, _ := validator.GetAEAD(authID[:]); found {
		t.Fatal("removed identity still authenticates")
	}
	authID = aead.CreateAuthID(legacy.CmdKey(), time.Now().Unix())
	if _, found, err := validator.GetAEAD(authID[:]); err != nil || !found {
		t.Fatal("removal affected standard identity")
	}
	if err := validator.Add(&protocol.MemoryUser{Email: "replacement", Account: other}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkUserValidator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := NewTimedUserValidator()

		for j := 0; j < 1500; j++ {
			id := uuid.New()
			v.Add(&protocol.MemoryUser{
				Email: "test",
				Account: toAccount(&Account{
					Id: id.String(),
				}),
			})
		}

		common.Close(v)
	}
}
