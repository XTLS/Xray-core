package bittorrent

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common"
)

// utpPacket builds the fixed 20-byte header defined by BEP 29.
func utpPacket(packetType, extension byte, tsDiff uint32, payload ...byte) []byte {
	b := make([]byte, 20)
	b[0] = packetType<<4 | 1
	b[1] = extension
	binary.BigEndian.PutUint16(b[2:4], 0x4a3f)     // connection_id, random
	binary.BigEndian.PutUint32(b[4:8], 0x8c3a91d2) // timestamp_microseconds, sender's clock
	binary.BigEndian.PutUint32(b[8:12], tsDiff)
	binary.BigEndian.PutUint32(b[12:16], 0x00100000) // wnd_size
	binary.BigEndian.PutUint16(b[16:18], 0x71ee)     // seq_nr, random in libutp/libtorrent
	binary.BigEndian.PutUint16(b[18:20], 0x0000)     // ack_nr
	return append(b, payload...)
}

func TestSniffUTP(t *testing.T) {
	selectiveAck := []byte{0, 4, 0xff, 0x00, 0xff, 0x00}
	wrongVersion := utpPacket(4, 0, 0)
	wrongVersion[0] = 4<<4 | 2

	cases := []struct {
		name    string
		payload []byte
		err     error
	}{
		{"syn", utpPacket(4, 0, 0), nil},
		{"syn with selective ack", append(utpPacket(4, 1, 0), selectiveAck...), nil},
		{"syn with extension bits", append(utpPacket(4, 2, 0), 0, 8, 1, 2, 3, 4, 5, 6, 7, 8), nil},
		{"extension bits with wrong length", append(utpPacket(4, 2, 0), 0, 4, 1, 2, 3, 4), errNotBittorrent},
		{"syn with nonzero timestamp_difference", utpPacket(4, 0, 0x1234), errNotBittorrent},
		{"syn with trailing payload", utpPacket(4, 0, 0, 'x'), errNotBittorrent},
		// txid 0x4100, no EDNS0: the worst case colliding with the uTP header
		{"dns query", []byte{
			0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 'a', 0x02, 'c', 'o', 0x00, 0x00, 0x01, 0x00, 0x01,
		}, errNotBittorrent},
		// the same collision at exactly 20 bytes, where the extension chain check
		// cannot help: QNAME is 2 characters, so qclass lands on ack_nr
		{"dns query the size of a bare header", []byte{
			0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 'a', 'b', 0x00, 0x00, 0x01, 0x00, 0x01,
		}, errNotBittorrent},
		{"established connection packets", utpPacket(0, 0, 0x5678, 'x', 'y', 'z'), errNotBittorrent},
		{"state", utpPacket(2, 0, 0x5678), errNotBittorrent},
		{"fin", utpPacket(1, 0, 0x5678), errNotBittorrent},
		{"wrong version", wrongVersion, errNotBittorrent},
		{"unknown packet type", utpPacket(5, 0, 0), errNotBittorrent},
		{"unknown extension", utpPacket(4, 2, 0), errNotBittorrent},
		{"extension chain past the datagram", utpPacket(4, 1, 0, 0, 8, 0xff), errNotBittorrent},
		{"selective ack not in multiples of 4", append(utpPacket(4, 1, 0), 0, 3, 0xff, 0x00, 0xff), errNotBittorrent},
		{"shorter than the header", utpPacket(4, 0, 0)[:19], common.ErrNoClue},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := SniffUTP(c.payload)
			if err != c.err {
				t.Fatalf("expected error %v, got %v", c.err, err)
			}
			if err == nil && h == nil {
				t.Fatal("expected a sniff header, got nil")
			}
		})
	}
}

// btHandshake builds the fixed 68 byte handshake defined by BEP 3.
func btHandshake() []byte {
	b := make([]byte, 0, 68)
	b = append(b, 19)
	b = append(b, "BitTorrent protocol"...)
	b = append(b, make([]byte, 8)...) // reserved
	ids := make([]byte, 40)           // info_hash and peer_id, arbitrary
	for i := range ids {
		ids[i] = byte(i)
	}
	return append(b, ids...)
}

func TestSniffBittorrent(t *testing.T) {
	wrongLength := btHandshake()
	wrongLength[0] = 20

	wrongProtocol := btHandshake()
	copy(wrongProtocol[1:20], "bitTorrent protocol")

	cases := []struct {
		name    string
		payload []byte
		err     error
	}{
		{"handshake", btHandshake(), nil},
		{"handshake cut to the matched prefix", btHandshake()[:20], nil},
		{"wrong pstrlen", wrongLength, errNotBittorrent},
		{"wrong protocol string", wrongProtocol, errNotBittorrent},
		{"tls client hello", []byte{
			0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
			0x9b, 0x1e, 0x4c, 0x7a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		}, errNotBittorrent},
		// an HTTP tracker announce is BitTorrent, but not this handshake
		{"http tracker announce", []byte("GET /announce?info_hash=aaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n"), errNotBittorrent},
		{"shorter than the matched prefix", btHandshake()[:19], common.ErrNoClue},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := SniffBittorrent(c.payload)
			if err != c.err {
				t.Fatalf("expected error %v, got %v", c.err, err)
			}
			if err == nil && h == nil {
				t.Fatal("expected a sniff header, got nil")
			}
		})
	}
}

// udpTrackerConnect builds the 16 byte connect request defined by BEP 15.
func udpTrackerConnect(magic uint64, action uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], magic)
	binary.BigEndian.PutUint32(b[8:12], action)
	binary.BigEndian.PutUint32(b[12:16], 0x2b8c41f7) // transaction_id, random
	return b
}

func TestSniffUDPTracker(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		err     error
	}{
		{"connect request", udpTrackerConnect(udpTrackerMagic, 0), nil},
		{"wrong magic", udpTrackerConnect(udpTrackerMagic+1, 0), errNotBittorrent},
		{"announce rather than connect", udpTrackerConnect(udpTrackerMagic, 1), errNotBittorrent},
		{"connect request with trailing bytes", append(udpTrackerConnect(udpTrackerMagic, 0), 'x'), errNotBittorrent},
		{"utp syn", utpPacket(4, 0, 0), errNotBittorrent},
		{"zeroed datagram", make([]byte, 16), errNotBittorrent},
		{"shorter than a connect request", udpTrackerConnect(udpTrackerMagic, 0)[:15], common.ErrNoClue},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := SniffUDPTracker(c.payload)
			if err != c.err {
				t.Fatalf("expected error %v, got %v", c.err, err)
			}
			if err == nil && h == nil {
				t.Fatal("expected a sniff header, got nil")
			}
		})
	}
}
