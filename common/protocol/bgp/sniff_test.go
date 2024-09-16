package bgp

import (
	"testing"
)

func TestSniffBGP(t *testing.T) {
	bgpPacket := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01}
	_, err := SniffBGP(bgpPacket)
	if err != nil {
		t.Errorf("Expected BGP protocol to be detected, got error: %v", err)
	}
}

func TestSniffNotBGP(t *testing.T) {
	nonBgpPacket := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := SniffBGP(nonBgpPacket)
	if err == nil {
		t.Errorf("Expected error for non-BGP packet, got none")
	}
}
