package bittorrent

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
)

// nodeID stands in for the 20 byte identifier every KRPC message carries.
var nodeID = strings.Repeat("A", 20)

func TestSniffDHT(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		err     error
	}{
		{"ping query", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:t2:aa1:y1:qe"), nil},
		{"get_peers query", []byte("d1:ad2:id20:" + nodeID + "9:info_hash20:" + nodeID + "e1:q9:get_peers1:t2:aa1:y1:qe"), nil},
		{"ping response", []byte("d1:rd2:id20:" + nodeID + "e1:t2:aa1:y1:re"), nil},
		{"response with an ip key ahead of r", []byte("d2:ip6:abcdef1:rd2:id20:" + nodeID + "e1:t2:aa1:y1:re"), nil},
		{"error", []byte("d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"), nil},
		{"query without a node id", []byte("d1:ad4:porti6881ee1:q4:ping1:t2:aa1:y1:qe"), errNotBittorrent},
		{"node id of the wrong length", []byte("d1:ad2:id19:" + nodeID[:19] + "e1:q4:ping1:t2:aa1:y1:qe"), errNotBittorrent},
		{"query without a method name", []byte("d1:ad2:id20:" + nodeID + "e1:t2:aa1:y1:qe"), errNotBittorrent},
		{"message without a transaction id", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:y1:qe"), errNotBittorrent},
		{"unknown message type", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:t2:aa1:y1:ze"), errNotBittorrent},
		{"message type that is not a string", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:t2:aa1:yi1ee"), errNotBittorrent},
		{"trailing byte past the dictionary", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:t2:aa1:y1:qex"), errNotBittorrent},
		{"dictionary left open", []byte("d1:ad2:id20:" + nodeID + "e1:q4:ping1:t2:aa1:y1:q"), errNotBittorrent},
		{"string longer than the datagram", []byte("d1:ad2:id99:" + nodeID + "e1:q4:ping1:t2:aa1:y1:qe"), errNotBittorrent},
		// guards the recursion bound rather than the protocol
		{"nested lists", []byte("d1:a" + strings.Repeat("l", 64) + strings.Repeat("e", 64) + "1:q4:ping1:t2:aa1:y1:qe"), errNotBittorrent},
		// datagrams the UDP sniffers see alongside the DHT
		{"dns query", []byte{
			0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 'a', 'b', 0x00, 0x00, 0x01, 0x00, 0x01,
		}, errNotBittorrent},
		{"utp syn", utpPacket(4, 0, 0), errNotBittorrent},
		{"udp tracker connect", udpTrackerConnect(udpTrackerMagic, 0), common.ErrNoClue},
		{"stun binding request", []byte{
			0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		}, errNotBittorrent},
		{"wireguard handshake initiation", []byte{
			0x01, 0x00, 0x00, 0x00, 0x3f, 0x2a, 0x91, 0xc4, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
		}, errNotBittorrent},
		{"plain text", []byte("this is not a bencoded dictionary"), errNotBittorrent},
		{"shorter than any message", []byte("d1:y1:qe"), common.ErrNoClue},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := SniffDHT(c.payload)
			if err != c.err {
				t.Fatalf("expected error %v, got %v", c.err, err)
			}
			if err == nil && h == nil {
				t.Fatal("expected a sniff header, got nil")
			}
		})
	}
}
