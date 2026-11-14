package encoding_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

func TestServerOnlyUUIDRoutes(t *testing.T) {
	validator := vmess.NewTimedUserValidator()
	defer validator.Close()
	original := &protocol.MemoryUser{Email: "alice", Level: 7, Account: toAccount(&vmess.Account{Id: "317530a8-3c1d-1234-8d8e-7cb70aedf158"})}
	if err := validator.Add(original); err != nil {
		t.Fatal(err)
	}
	r := new(router.Router)
	config := &router.Config{Rule: []*router.RoutingRule{{RuleTag: "routes", UserRouteList: &net.PortList{Range: []*net.PortRange{{From: 0, To: 1}, {From: 300, To: 300}, {From: 65535, To: 65535}}}}}}
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := validator.SetRouteSource(r, "vm"); err != nil {
		t.Fatal(err)
	}
	history := NewSessionHistory()
	defer history.Close()
	packet := func(route int, client *ClientSession) []byte {
		user := &protocol.MemoryUser{Account: toAccount(&vmess.Account{Id: fmt.Sprintf("317530a8-3c1d-%04x-8d8e-7cb70aedf158", route)})}
		var b bytes.Buffer
		if err := client.EncodeRequestHeader(&protocol.RequestHeader{Version: 1, User: user, Command: protocol.RequestCommandTCP, Address: net.DomainAddress("example.test"), Port: 443, Security: protocol.SecurityType_AES128_GCM}, &b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	decode := func(wire []byte) (*protocol.RequestHeader, net.Port, error) {
		s := NewServerSession(validator, history)
		defer s.Close()
		req, err := s.DecodeRequestHeader(bytes.NewReader(wire), false)
		return req, s.UserRoute(), err
	}
	for _, route := range []int{0, 1, 300, 65535, 4660} {
		wire := packet(route, NewClientSession(context.Background(), 0))
		req, got, err := decode(wire)
		if err != nil || req.User != original || int(got) != route {
			t.Fatalf("route=%d got=%d req=%v err=%v", route, got, req, err)
		}
		if _, _, err := decode(wire); err == nil {
			t.Fatal("replayed header accepted")
		}
	}
	for _, offset := range []int{0, 17, 34, 50} {
		wire := packet(300, NewClientSession(context.Background(), 0))
		wire[offset] ^= 1
		if _, _, err := decode(wire); err == nil {
			t.Fatal("tampered header accepted", offset)
		}
	}
	if _, _, err := decode(packet(2, NewClientSession(context.Background(), 0))); err == nil {
		t.Fatal("undeclared route accepted")
	}
	// The same body key/nonce under two valid aliases is one original-user session.
	client := NewClientSession(context.Background(), 0)
	if _, _, err := decode(packet(0, client)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decode(packet(300, client)); err == nil {
		t.Fatal("cross-alias session replay accepted")
	}
	if err := r.RemoveRule("routes"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decode(packet(300, NewClientSession(context.Background(), 0))); err == nil {
		t.Fatal("removed route accepted")
	}
	if req, _, err := decode(packet(4660, NewClientSession(context.Background(), 0))); err != nil || req.User != original {
		t.Fatal("rule removal broke original UUID", err)
	}
}
