package xicmp_test

import (
	"fmt"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestICMPEchoMarshal(t *testing.T) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  1,
			Data: nil,
		},
	}
	ICMPTypeEcho, _ := msg.Marshal(nil)
	fmt.Println("ICMPTypeEcho", len(ICMPTypeEcho), ICMPTypeEcho)

	msg = icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  1,
			Data: nil,
		},
	}
	ICMPTypeEchoReply, _ := msg.Marshal(nil)
	fmt.Println("ICMPTypeEchoReply", len(ICMPTypeEchoReply), ICMPTypeEchoReply)

	msg = icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  1,
			Data: nil,
		},
	}
	ICMPTypeEchoRequest, _ := msg.Marshal(nil)
	fmt.Println("ICMPTypeEchoRequest", len(ICMPTypeEchoRequest), ICMPTypeEchoRequest)

	msg = icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  1,
			Data: nil,
		},
	}
	V6ICMPTypeEchoReply, _ := msg.Marshal(nil)
	fmt.Println("V6ICMPTypeEchoReply", len(V6ICMPTypeEchoReply), V6ICMPTypeEchoReply)

	if len(ICMPTypeEcho) != 8 {
		t.Fatalf("ICMPTypeEcho len=%d", len(ICMPTypeEcho))
	}
	if len(ICMPTypeEchoReply) != 8 {
		t.Fatalf("ICMPTypeEchoReply len=%d", len(ICMPTypeEchoReply))
	}
	if len(ICMPTypeEchoRequest) != 8 {
		t.Fatalf("ICMPTypeEchoRequest len=%d", len(ICMPTypeEchoRequest))
	}
	if len(V6ICMPTypeEchoReply) != 8 {
		t.Fatalf("V6ICMPTypeEchoReply len=%d", len(V6ICMPTypeEchoReply))
	}
}
