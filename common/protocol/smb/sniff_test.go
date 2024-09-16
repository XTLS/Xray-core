package smb

import (
	"testing"
)

func TestSniffSMB1(t *testing.T) {
	smbPacket := []byte{0xFF, 0x53, 0x4D, 0x42}
	_, err := SniffSMB(smbPacket)
	if err != nil {
		t.Errorf("Expected SMB1 protocol to be detected, got error: %v", err)
	}
}

func TestSniffSMB2(t *testing.T) {
	smbPacket := []byte{0xFE, 0x53, 0x4D, 0x42}
	_, err := SniffSMB(smbPacket)
	if err != nil {
		t.Errorf("Expected SMB2/SMB3 protocol to be detected, got error: %v", err)
	}
}

func TestSniffNotSMB(t *testing.T) {
	nonSmbPacket := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := SniffSMB(nonSmbPacket)
	if err == nil {
		t.Errorf("Expected error for non-SMB packet, got none")
	}
}
