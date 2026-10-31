package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
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
	const cont = "HTTP/1.1 100 Continue\r\n\r\n"
	const hint = "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\n"
	for _, tc := range []struct{ name, interim string }{
		{"no_interim", ""},
		{"continue", cont},
		{"early_hints", hint},
		{"multiple_hints", hint + hint},
		{"continue_and_hints", cont + hint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.interim + "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
			r := bufio.NewReader(iotest.OneByteReader(strings.NewReader(payload)))
			req, err := http.NewRequest("GET", "http://example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			var forwarded bytes.Buffer
			resp, err := readResponseAndHandle100Continue(r, req, &forwarded)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || string(body) != "hello" || forwarded.String() != tc.interim {
				t.Fatalf("status=%d body=%q forwarded=%q; want 200, hello, %q", resp.StatusCode, body, forwarded.String(), tc.interim)
			}
		})
	}
}

func TestReadResponseAndHandle100ContinueStopsAtSwitchingProtocols(t *testing.T) {
	const upgrade = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: example\r\n\r\n"
	r := bufio.NewReader(iotest.OneByteReader(strings.NewReader(upgrade + "opaque")))
	var forwarded bytes.Buffer
	resp, err := readResponseAndHandle100Continue(r, &http.Request{Method: "GET"}, &forwarded)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	remaining, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || forwarded.Len() != 0 || string(remaining) != "opaque" {
		t.Fatalf("status=%d forwarded=%q remaining=%q", resp.StatusCode, forwarded.String(), remaining)
	}
}
