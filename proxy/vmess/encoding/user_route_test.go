package encoding_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/aead"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

func TestDynamicUUIDRouting(t *testing.T) {
	user := &protocol.MemoryUser{
		Email: "route@example.com",
		Account: toAccount(&vmess.Account{
			Id: "317530a8-3c1d-1234-8d8e-7cb70aedf158", UserRoute: true,
		}),
	}
	validator := vmess.NewTimedUserValidator()
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	history := NewSessionHistory()
	t.Cleanup(func() { history.Close() })
	for _, command := range []protocol.RequestCommand{protocol.RequestCommandTCP, protocol.RequestCommandUDP, protocol.RequestCommandMux} {
		for _, route := range []int{0, 1, 4660, 4661, 65535} {
			t.Run(fmt.Sprintf("command=%d/route=%d", command, route), func(t *testing.T) {
				request := &protocol.RequestHeader{
					Version: 1, Command: command, Address: net.DomainAddress("example.com"), Port: 443,
					Security: protocol.SecurityType_AES128_GCM,
					User: &protocol.MemoryUser{Account: toAccount(&vmess.Account{
						Id: fmt.Sprintf("317530a8-3c1d-%04x-8d8e-7cb70aedf158", route), UserRoute: true,
					})},
				}
				var wire bytes.Buffer
				if err := NewClientSession(context.Background(), 0).EncodeRequestHeader(request, &wire); err != nil {
					t.Fatal(err)
				}
				packet := append([]byte(nil), wire.Bytes()...)
				server := NewServerSession(validator, history)
				decoded, err := server.DecodeRequestHeader(&wire, false)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.User != user {
					t.Fatal("route variant changed the authenticated user")
				}
				if got := server.UserRoute(); got != net.Port(route) {
					t.Fatalf("route = %d, want %d", got, route)
				}
				if _, err := NewServerSession(validator, history).DecodeRequestHeader(bytes.NewReader(packet), false); err == nil {
					t.Fatal("replayed route request accepted")
				}
			})
		}
	}
}

func TestUserRouteRejectsInvalidRequests(t *testing.T) {
	const id = "317530a8-3c1d-0000-8d8e-7cb70aedf158"
	for _, tc := range []struct {
		name           string
		client, server bool
		clientID       string
		mutate         func([]byte)
		tamper         bool
	}{
		{name: "disabled-client", server: true},
		{name: "disabled-server", client: true},
		{name: "wrong-identity", client: true, server: true, clientID: "317530a8-3c1d-0001-8d8e-7cb70aedf159"},
		{name: "default-UUID-change", clientID: "317530a8-3c1d-0001-8d8e-7cb70aedf158"},
		{name: "tampered-ciphertext", client: true, server: true, tamper: true},
		{name: "missing-marker", client: true, server: true, mutate: func(b []byte) { b[36] = 0 }},
		{name: "unknown-marker", client: true, server: true, mutate: func(b []byte) { b[36] = 2 }},
		{name: "short-route", client: true, server: true, mutate: func(b []byte) { b[35] = 0x10 | (b[35] & 15) }},
		{name: "unknown-version", client: true, server: true, mutate: func(b []byte) { b[0] = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientID := tc.clientID
			if clientID == "" {
				clientID = id
			}
			account := toAccount(&vmess.Account{Id: clientID, UserRoute: tc.client}).(*vmess.MemoryAccount)
			request := &protocol.RequestHeader{
				Version: 1, Command: protocol.RequestCommandTCP, Address: net.LocalHostIP, Port: 443,
				Security: protocol.SecurityType_AES128_GCM, User: &protocol.MemoryUser{Account: account},
			}
			var wire bytes.Buffer
			if err := NewClientSession(context.Background(), 0).EncodeRequestHeader(request, &wire); err != nil {
				t.Fatal(err)
			}
			packet := wire.Bytes()
			if tc.mutate != nil {
				var key, authID [16]byte
				copy(key[:], account.CmdKey())
				copy(authID[:], packet[:16])
				plain, _, _, err := aead.OpenVMessAEADHeader(key, authID, bytes.NewReader(packet[16:]))
				if err != nil {
					t.Fatal(err)
				}
				tc.mutate(plain)
				hash := fnv.New32a()
				hash.Write(plain[:len(plain)-4])
				binary.BigEndian.PutUint32(plain[len(plain)-4:], hash.Sum32())
				packet = aead.SealVMessAEADHeader(key, plain)
			}
			if tc.tamper {
				packet[len(packet)-1] ^= 1
			}
			validator := vmess.NewTimedUserValidator()
			if err := validator.Add(&protocol.MemoryUser{Account: toAccount(&vmess.Account{Id: id, UserRoute: tc.server})}); err != nil {
				t.Fatal(err)
			}
			history := NewSessionHistory()
			t.Cleanup(func() { history.Close() })
			server := NewServerSession(validator, history)
			if _, err := server.DecodeRequestHeader(bytes.NewReader(packet), false); err == nil {
				t.Fatal("invalid request accepted")
			}
			if server.UserRoute() != 0 {
				t.Fatal("failed request exposed a route")
			}
		})
	}
}
