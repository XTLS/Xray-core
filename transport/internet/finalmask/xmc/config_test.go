package xmc

import (
	"net"
	"strings"
	"testing"
)

func TestClientRejectsLongLegacyPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	profiles := []loginProfile{{Username: "TestUser"}}
	publicKey := []byte{0x01}

	if _, err := newClientConn(client, profiles, strings.Repeat("p", MaxLegacyPasswordLength), publicKey, "localhost", nil); err != nil {
		t.Fatalf("password of %d bytes was rejected: %v", MaxLegacyPasswordLength, err)
	}
	if _, err := newClientConn(client, profiles, strings.Repeat("p", MaxLegacyPasswordLength+1), publicKey, "localhost", nil); err == nil {
		t.Fatal("expected the long password to be rejected")
	}
}
