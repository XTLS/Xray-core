package http

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteHTTPAuthFailure_Reject(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHTTPAuthFailure(&buf, AuthFailureBehavior_REJECT); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP/1.1 407 Proxy Authentication Required\r\n") {
		t.Fatalf("REJECT: unexpected status line: %q", out)
	}
	if !strings.Contains(out, "Proxy-Authenticate: Basic realm=\"proxy\"") {
		t.Fatalf("REJECT: missing Proxy-Authenticate header: %q", out)
	}
}

func TestWriteHTTPAuthFailure_Drop(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHTTPAuthFailure(&buf, AuthFailureBehavior_DROP); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("DROP: expected empty output, got %v", buf.Bytes())
	}
}

func TestWriteHTTPAuthFailure_HTTP400(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHTTPAuthFailure(&buf, AuthFailureBehavior_HTTP400); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "HTTP/1.1 400 Bad Request\r\n") {
		t.Fatalf("HTTP400: unexpected status line: %q", out)
	}
	if strings.Contains(out, "Proxy-") {
		t.Fatalf("HTTP400: response must not advertise proxy headers: %q", out)
	}
}
