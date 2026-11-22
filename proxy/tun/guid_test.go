package tun_test

import (
	"testing"

	"github.com/xtls/xray-core/proxy/tun"
)

func TestParseGUID(t *testing.T) {
	for _, c := range []struct {
		guid string
		raw  [16]byte
	}{
		{"00000000-0000-0000-0000-000000000000", [16]byte{}},
		{"00010203-0405-0607-0809-0a0b0c0d0e0f", [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		{"6ba7b810-9dad-11d1-80b4-00c04fd430c8", [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}},
		{"6BA7B810-9DAD-11D1-80B4-00C04FD430C8", [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}},
		{"ffffffff-ffff-ffff-ffff-ffffffffffff", [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		raw, err := tun.ParseGUID(c.guid)
		if err != nil {
			t.Errorf("ParseGUID(%q) failed: %v", c.guid, err)
			continue
		}
		if raw != c.raw {
			t.Errorf("ParseGUID(%q) = %x, want %x", c.guid, raw, c.raw)
		}
	}
}

func TestParseGUIDInvalid(t *testing.T) {
	for _, guid := range []string{
		"",
		" ",
		"xray0",
		// right characters, wrong places of the hyphens
		"6ba7b8109-dad-11d1-80b4-00c04fd430c8",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c88",
		"6ba7b810-9dad-11d1-80b4_00c04fd430c8",
		// not hexadecimal
		"6ba7b81g-9dad-11d1-80b4-00c04fd430c8",
		"6ba7b810-9dad-11d1-80b4-00c04fd430cg",
		// forms other than the canonical one
		"6ba7b8109dad11d180b400c04fd430c8",
		"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",
		"urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8 ",
	} {
		if raw, err := tun.ParseGUID(guid); err == nil {
			t.Errorf("ParseGUID(%q) = %x, want an error", guid, raw)
		}
	}
}
