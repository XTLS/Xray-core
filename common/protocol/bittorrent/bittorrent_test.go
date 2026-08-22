package bittorrent_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/bittorrent"
)

// utpPacket builds the 20 byte fixed header described by BEP 29.
func utpPacket(packetType, extension byte, timestamp uint32) []byte {
	b := make([]byte, 20)
	b[0] = packetType<<4 | 1
	b[1] = extension
	binary.BigEndian.PutUint16(b[2:4], 0x1234)
	binary.BigEndian.PutUint32(b[4:8], timestamp)
	binary.BigEndian.PutUint32(b[8:12], 0)
	binary.BigEndian.PutUint32(b[12:16], 0x10000)
	binary.BigEndian.PutUint16(b[16:18], 1)
	binary.BigEndian.PutUint16(b[18:20], 0)
	return b
}

// Extension records follow the fixed header rather than sitting inside it.
func utpPacketWithSelectiveAck() []byte {
	b := utpPacket(2, 1, 1)
	return append(b, 0, 4, 0xFF, 0x00, 0xFF, 0x00)
}

func utpPacketWith(mutate func([]byte)) []byte {
	b := utpPacket(4, 0, 1)
	mutate(b)
	return b
}

// A WireGuard handshake initiation is a message type of 1 followed by three
// reserved zero bytes, which land on the version, extension and connection id
// fields. It opens a session, so the sniffer sees it.
func wireGuardInitiation() []byte {
	b := make([]byte, 148)
	b[0] = 0x01
	for i := 4; i < len(b); i++ {
		b[i] = byte(i * 7)
	}
	return b
}

func dnsQuery() []byte {
	return []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
}

func TestSniffUTP(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"syn", utpPacket(4, 0, 0x0102FF00), true},
		{"data", utpPacket(0, 0, 1), true},
		{"state with a large timestamp", utpPacket(2, 0, 0xFFFFFFFF), true},
		{"selective ack extension", utpPacketWithSelectiveAck(), true},
		{"shorter than the header", []byte{0x41, 0, 0, 0}, false},
		{"wrong version", utpPacketWith(func(b []byte) { b[0] = 0x42 }), false},
		{"unknown packet type", utpPacketWith(func(b []byte) { b[0] = 0x51 }), false},
		{"zero connection id", utpPacketWith(func(b []byte) { binary.BigEndian.PutUint16(b[2:4], 0) }), false},
		{"implausible window size", utpPacketWith(func(b []byte) { binary.BigEndian.PutUint32(b[12:16], 0xFFFFFFFF) }), false},
		{"unknown extension type", utpPacketWith(func(b []byte) { b[1] = 3 }), false},
		{"truncated extension record", append(utpPacket(4, 1, 1), 0), false},
		{"wireguard handshake initiation", wireGuardInitiation(), false},
		{"dns query", dnsQuery(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := bittorrent.SniffUTP(c.payload)
			if c.want {
				if err != nil || h == nil {
					t.Fatalf("expected a uTP header, got header %v err %v", h, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error, got header %v", h)
			}
		})
	}
}

// A payload that stops mid header leaves the sniffer without a verdict, while a
// well formed packet that is not uTP is a definite reject. The dispatcher treats
// the two differently, so the distinction is asserted.
func TestSniffUTPErrorKind(t *testing.T) {
	if _, err := bittorrent.SniffUTP([]byte{0x41, 0}); !errors.Is(err, common.ErrNoClue) {
		t.Fatalf("a short payload should give no clue, got %v", err)
	}
	if _, err := bittorrent.SniffUTP(wireGuardInitiation()); errors.Is(err, common.ErrNoClue) {
		t.Fatal("a complete non-uTP packet should be rejected outright")
	}
}

func TestSniffBittorrent(t *testing.T) {
	handshake := append([]byte{19}, []byte("BitTorrent protocol")...)
	handshake = append(handshake, make([]byte, 8)...)
	if _, err := bittorrent.SniffBittorrent(handshake); err != nil {
		t.Fatalf("expected the cleartext handshake to be recognised: %v", err)
	}
	if _, err := bittorrent.SniffBittorrent([]byte("GET /announce HTTP/1.1\r\nHost: t\r\n\r\n")); err == nil {
		t.Fatal("expected an error for a non-BitTorrent payload")
	}
	if _, err := bittorrent.SniffBittorrent([]byte{19, 'B'}); !errors.Is(err, common.ErrNoClue) {
		t.Fatal("a short payload should give no clue")
	}
}
