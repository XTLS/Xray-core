package tls_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/common/protocol/tls"
)

func clientHello(t testing.TB) []byte {
	t.Helper()
	// Generated using Python ssl.SSLContext.wrap_bio, with www.youtube.com as SNI.
	b, err := os.ReadFile("testdata/clienthello.bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func record(payload []byte) []byte {
	b := []byte{0x16, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(b[3:], uint16(len(payload)))
	return append(b, payload...)
}

func checkPrefixes(t *testing.T, b []byte) {
	t.Helper()
	for n := 1; n < len(b); n++ {
		if _, err := SniffTLS(b[:n]); err != protocol.ErrProtoNeedMoreData {
			t.Fatalf("prefix %d/%d: %v", n, len(b), err)
		}
	}
	before := bytes.Clone(b)
	h, err := SniffTLS(b)
	if err != nil || h.Domain() != "www.youtube.com" {
		t.Fatalf("complete hello: %v, %v", h, err)
	}
	if !bytes.Equal(before, b) {
		t.Fatal("sniffer modified the forwarded input")
	}
}

func TestTLSFragmentedClientHello(t *testing.T) {
	b := clientHello(t)
	checkPrefixes(t, b)
	for split := 1; split < len(b)-5; split++ {
		joined := append(record(b[5:5+split]), record(b[5+split:])...)
		checkPrefixes(t, joined)
	}
	var tinyRecords []byte
	for _, v := range b[5:] {
		tinyRecords = append(tinyRecords, record([]byte{v})...)
	}
	checkPrefixes(t, tinyRecords)
	// A following handshake/application record must not affect ClientHello parsing.
	check := append(bytes.Clone(b[5:]), 0x0b, 0, 0, 0)
	h, err := SniffTLS(record(check))
	if err != nil || h.Domain() != "www.youtube.com" {
		t.Fatalf("trailing handshake: %v, %v", h, err)
	}
}

func TestTLSCompleteUnknownAndMalformed(t *testing.T) {
	noSNI, err := os.ReadFile("testdata/clienthello-no-sni.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{
		noSNI,
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x16, 3, 1, 0, 0},
		{0x16, 3, 1, 0x40, 1},
		record([]byte{2, 0, 0, 0}),
		record([]byte{1, 0, 0, 0}),
	} {
		if _, err := SniffTLS(b); err == nil || err == protocol.ErrProtoNeedMoreData {
			t.Fatalf("complete unknown/malformed input classified as valid or incomplete: %x: %v", b, err)
		}
	}
}

func TestTLSLargeClientHello(t *testing.T) {
	b := clientHello(t)
	// Extend this fixture's final padding extension to make a 32 KiB handshake.
	const extensionsOffset, paddingOffset = 116, 291
	if binary.BigEndian.Uint16(b[paddingOffset:]) != 21 || paddingOffset+4+int(binary.BigEndian.Uint16(b[paddingOffset+2:])) != len(b) {
		t.Fatal("fixture no longer ends in the expected padding extension")
	}
	delta := 32768 - (len(b) - 5)
	binary.BigEndian.PutUint16(b[extensionsOffset:], binary.BigEndian.Uint16(b[extensionsOffset:])+uint16(delta))
	binary.BigEndian.PutUint16(b[paddingOffset+2:], binary.BigEndian.Uint16(b[paddingOffset+2:])+uint16(delta))
	b = append(b, make([]byte, delta)...)
	helloLength := len(b) - 9
	b[6], b[7], b[8] = byte(helloLength>>16), byte(helloLength>>8), byte(helloLength)
	joined := append(record(b[5:5+16384]), record(b[5+16384:])...)
	for _, n := range []int{1, 4, 5, 16388, 16389, 16390, 16394, len(joined) - 1} {
		if _, err := SniffTLS(joined[:n]); err != protocol.ErrProtoNeedMoreData {
			t.Fatalf("prefix %d: %v", n, err)
		}
	}
	h, err := SniffTLS(joined)
	if err != nil || h.Domain() != "www.youtube.com" {
		t.Fatalf("large hello: %v %v", h, err)
	}
}

func FuzzSniffTLS(f *testing.F) {
	f.Add(clientHello(f))
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		before := bytes.Clone(b)
		SniffTLS(b)
		if !bytes.Equal(before, b) {
			t.Fatal("input modified")
		}
	})
}
