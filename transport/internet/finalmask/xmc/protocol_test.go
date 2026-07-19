package xmc

import (
	"bytes"
	"strings"
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

func TestPacketWithLengthReportsWireBytes(t *testing.T) {
	var wire bytes.Buffer
	written, err := writePacketWithLength(&wire, 0x03)
	if err != nil {
		t.Fatal(err)
	}
	if written != 2 || !bytes.Equal(wire.Bytes(), []byte{0x01, 0x03}) {
		t.Fatalf("wire = %x, length = %d", wire.Bytes(), written)
	}

	packet, read, err := readPacketWithLength(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if packet.packetID != 0x03 || read != written {
		t.Fatalf("packet ID = %d, read = %d, written = %d", packet.packetID, read, written)
	}
}

func TestReadPacketRejectsNonCanonicalLengthVarint(t *testing.T) {
	_, _, err := readPacketWithLength(bytes.NewReader([]byte{0x81, 0x00, 0x03}))
	if err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("error = %v", err)
	}
}

func TestVarintRejectsOversizedFifthByte(t *testing.T) {
	var value Varint
	err := value.readFrom(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0x1f}))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v", err)
	}
}
