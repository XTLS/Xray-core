package socks_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/proxy/socks"
)

func TestWriteSocks5AuthFailure_Reject(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5AuthFailureForTest(&buf, AuthFailureBehavior_REJECT, 0x05, 0xFF); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.Bytes()
	want := []byte{0x05, 0xFF}
	if !bytes.Equal(got, want) {
		t.Fatalf("REJECT: got %v, want %v", got, want)
	}
}

func TestWriteSocks5AuthFailure_Drop(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5AuthFailureForTest(&buf, AuthFailureBehavior_DROP, 0x05, 0xFF); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("DROP: expected empty output, got %v", buf.Bytes())
	}
}

func TestWriteSocks5AuthFailure_HTTP400(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSocks5AuthFailureForTest(&buf, AuthFailureBehavior_HTTP400, 0x05, 0xFF); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP/1.1 400 Bad Request\r\n") {
		t.Fatalf("HTTP400: unexpected status line: %q", out)
	}
	if strings.Contains(out, "Proxy-") {
		t.Fatalf("HTTP400: response must not advertise proxy headers: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Fatalf("HTTP400: response must end with CRLFCRLF: %q", out)
	}
}
