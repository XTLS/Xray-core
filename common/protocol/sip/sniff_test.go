package sip

import (
	"testing"
)

func TestSniffSIPInvite(t *testing.T) {
	sipPacket := []byte("INVITE sip:user@example.com SIP/2.0")
	_, err := SniffSIP(sipPacket)
	if err != nil {
		t.Errorf("Expected SIP protocol to be detected, got error: %v", err)
	}
}

func TestSniffSIPAck(t *testing.T) {
	sipPacket := []byte("ACK sip:user@example.com SIP/2.0")
	_, err := SniffSIP(sipPacket)
	if err != nil {
		t.Errorf("Expected SIP protocol to be detected, got error: %v", err)
	}
}

func TestSniffNotSIP(t *testing.T) {
	nonSipPacket := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := SniffSIP(nonSipPacket)
	if err == nil {
		t.Errorf("Expected error for non-SIP packet, got none")
	}
}
