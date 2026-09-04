package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A malformed upstream response containing a bare '\n' before the real
// status line used to crash readResponseAndHandle100Continue: the first
// ReadSlice('\n') returns fewer than 4 bytes, and slicing
// ResponseHeader1xx[len(ResponseHeader1xx)-4:] panicked with a negative
// index instead of returning an error.
func TestReadResponseAndHandle100ContinueDoesNotPanicOnEarlyNewline(t *testing.T) {
	payload := "X\nHTTP/1.1 100 Continue\r\n\r\n" + strings.Repeat("A", 40)
	r := bufio.NewReader(bytes.NewReader([]byte(payload)))
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Must not panic; a parse error for the garbage trailing bytes is fine.
	_, _ = readResponseAndHandle100Continue(r, req, io.Discard)
}

func TestReadResponseAndHandle100ContinueForwardsAndParsesFinalResponse(t *testing.T) {
	payload := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	r := bufio.NewReader(bytes.NewReader([]byte(payload)))
	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	var forwarded bytes.Buffer
	resp, err := readResponseAndHandle100Continue(r, req, &forwarded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(forwarded.String(), "100 Continue") {
		t.Fatalf("expected 1xx response to be forwarded, got %q", forwarded.String())
	}
}
