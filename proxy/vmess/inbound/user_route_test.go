package inbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
)

func TestDuplicateRouteUserDoesNotReserveEmail(t *testing.T) {
	h := &Handler{clients: vmess.NewTimedUserValidator(), usersByEmail: newUserByEmail(&DefaultConfig{})}
	ctx := context.Background()
	makeUser := func(id, email string) *protocol.MemoryUser {
		a, err := (&vmess.Account{Id: id, UserRoute: true}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.MemoryUser{Email: email, Account: a}
	}
	first := makeUser("317530a8-3c1d-1234-8d8e-7cb70aedf158", "first")
	duplicate := makeUser("317530a8-3c1d-ffff-8d8e-7cb70aedf158", "second")
	if err := h.AddUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := h.AddUser(ctx, duplicate); err == nil {
		t.Fatal("duplicate accepted")
	}
	if h.GetUser(ctx, "second") != nil || h.GetUsersCount(ctx) != 1 {
		t.Fatal("failed add changed users")
	}
	if err := h.RemoveUser(ctx, "FIRST"); err != nil {
		t.Fatal(err)
	}
	if err := h.AddUser(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	if h.GetUser(ctx, "SECOND") != duplicate {
		t.Fatal("replacement user missing")
	}
}

func TestRemoveUserUsesSameEmailNormalizationAsAdd(t *testing.T) {
	h := &Handler{clients: vmess.NewTimedUserValidator(), usersByEmail: newUserByEmail(&DefaultConfig{})}
	defer h.clients.Close()
	ctx := context.Background()
	var users []*protocol.MemoryUser
	for i, email := range []string{"\u00b5@example", "\u03bc@example"} {
		id := []string{"317530a8-3c1d-1234-8d8e-7cb70aedf158", "417530a8-3c1d-1234-8d8e-7cb70aedf158"}[i]
		account, err := (&vmess.Account{Id: id}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		user := &protocol.MemoryUser{Email: email, Account: account}
		if err := h.AddUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		users = append(users, user)
	}
	if err := h.RemoveUser(ctx, users[1].Email); err != nil {
		t.Fatal(err)
	}
	remaining := h.clients.GetUsers()
	if len(remaining) != 1 || remaining[0] != users[0] || h.GetUser(ctx, users[0].Email) != users[0] || h.GetUser(ctx, users[1].Email) != nil {
		t.Fatal("email index and authenticated account removal disagree")
	}
}
