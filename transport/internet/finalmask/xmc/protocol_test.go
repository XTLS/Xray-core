package xmc

import (
	"bytes"
	"testing"
)

func TestReadPacketDoesNotConsumeFollowingPacket(t *testing.T) {
	data := []byte{0x01, 0x80, 0x01, 0x00}
	r := bytes.NewReader(data)
	if _, err := readPacket(r); err == nil {
		t.Fatal("expected truncated packet ID to fail")
	}
	pkt, err := readPacket(r)
	if err != nil {
		t.Fatalf("read following packet: %v", err)
	}
	if pkt.packetID != 0 {
		t.Fatalf("packet ID = %d", pkt.packetID)
	}
}
