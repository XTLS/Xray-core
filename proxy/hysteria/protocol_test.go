package hysteria

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseUDPMessage(t *testing.T) {
	want := &UDPMessage{PacketID: 1, FragID: 2, FragCount: 3, Addr: "example.com:443", Data: []byte("hello")}
	msg := make([]byte, want.Size())
	want.Serialize(msg)

	for _, lastAddr := range []string{"", want.Addr, "other:1"} {
		got := new(UDPMessage)
		if err := parseUDPMessage(msg, lastAddr, got); err != nil {
			t.Fatalf("lastAddr %q: %v", lastAddr, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("lastAddr %q: got %+v, want %+v", lastAddr, got, want)
		}
	}
}

func TestParseUDPMessageInvalid(t *testing.T) {
	msg := &UDPMessage{Addr: "example.com:443", Data: []byte("hello")}
	buf := make([]byte, msg.Size())
	msg.Serialize(buf)

	zeroAddrLen := bytes.Clone(buf)
	zeroAddrLen[8] = 0 // Address length varint follows the 8-byte header

	noData := &UDPMessage{Addr: msg.Addr}
	noDataBuf := make([]byte, noData.Size())
	noData.Serialize(noDataBuf)

	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"short header", buf[:7]},
		{"zero address length", zeroAddrLen},
		{"no data after address", noDataBuf},
	} {
		if _, err := ParseUDPMessage(tc.msg); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
