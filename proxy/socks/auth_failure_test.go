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

func TestSocks4AuthFailureBehaviorWithPassword(t *testing.T) {
	tests := []struct {
		name     string
		behavior AuthFailureBehavior
		check    func(t *testing.T, out string)
	}{
		{
			name:     "reject",
			behavior: AuthFailureBehavior_REJECT,
			check: func(t *testing.T, out string) {
				want := string([]byte{0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
				if out != want {
					t.Fatalf("unexpected SOCKS4 reject response: got % X, want % X", []byte(out), []byte(want))
				}
			},
		},
		{
			name:     "drop",
			behavior: AuthFailureBehavior_DROP,
			check: func(t *testing.T, out string) {
				if out != "" {
					t.Fatalf("DROP: expected empty response, got % X", []byte(out))
				}
			},
		},
		{
			name:     "http400",
			behavior: AuthFailureBehavior_HTTP400,
			check: func(t *testing.T, out string) {
				if !strings.HasPrefix(out, "HTTP/1.1 400 Bad Request\r\n") {
					t.Fatalf("HTTP400: unexpected response: %q", out)
				}
				if strings.Contains(out, "Proxy-") {
					t.Fatalf("HTTP400: response must not advertise proxy headers: %q", out)
				}
			},
		},
	}

	input := []byte{0x04, 0x01, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04, 0x00}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := NewServerSessionForTest(&ServerConfig{
				AuthType:            AuthType_PASSWORD,
				AuthFailureBehavior: test.behavior,
			})
			var out bytes.Buffer
			_, err := session.Handshake(bytes.NewReader(input), &out)
			if err == nil {
				t.Fatal("expected SOCKS4 auth error")
			}
			test.check(t, out.String())
		})
	}
}

func TestSocks5BadPasswordDoesNotLeakMethodInStealthModes(t *testing.T) {
	tests := []struct {
		name     string
		behavior AuthFailureBehavior
		check    func(t *testing.T, out string)
	}{
		{
			name:     "reject",
			behavior: AuthFailureBehavior_REJECT,
			check: func(t *testing.T, out string) {
				want := string([]byte{0x05, 0x02, 0x01, 0xFF})
				if out != want {
					t.Fatalf("REJECT: got % X, want % X", []byte(out), []byte(want))
				}
			},
		},
		{
			name:     "drop",
			behavior: AuthFailureBehavior_DROP,
			check: func(t *testing.T, out string) {
				if out != "" {
					t.Fatalf("DROP: expected empty response, got % X", []byte(out))
				}
			},
		},
		{
			name:     "http400",
			behavior: AuthFailureBehavior_HTTP400,
			check: func(t *testing.T, out string) {
				if strings.HasPrefix(out, string([]byte{0x05, 0x02})) {
					t.Fatalf("HTTP400 leaked SOCKS method selection before auth failure: % X", []byte(out))
				}
				if !strings.HasPrefix(out, "HTTP/1.1 400 Bad Request\r\n") {
					t.Fatalf("HTTP400: unexpected response: %q", out)
				}
			},
		},
	}

	input := []byte{0x05, 0x01, 0x02, 0x01, 0x01, 'u', 0x03, 'b', 'a', 'd'}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := NewServerSessionForTest(&ServerConfig{
				AuthType:            AuthType_PASSWORD,
				Accounts:            map[string]string{"u": "p"},
				AuthFailureBehavior: test.behavior,
			})
			var out bytes.Buffer
			_, err := session.Handshake(bytes.NewReader(input), &out)
			if err == nil {
				t.Fatal("expected bad-password auth error")
			}
			test.check(t, out.String())
		})
	}
}

func TestSocks5OptimisticPasswordAuthSucceedsInStealthModes(t *testing.T) {
	tests := []struct {
		name     string
		behavior AuthFailureBehavior
	}{
		{name: "drop", behavior: AuthFailureBehavior_DROP},
		{name: "http400", behavior: AuthFailureBehavior_HTTP400},
	}

	input := []byte{
		0x05, 0x01, 0x02,
		0x01, 0x01, 'u', 0x01, 'p',
		0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50,
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := NewServerSessionForTest(&ServerConfig{
				AuthType:            AuthType_PASSWORD,
				Accounts:            map[string]string{"u": "p"},
				AuthFailureBehavior: test.behavior,
			})
			var out bytes.Buffer
			request, err := session.Handshake(bytes.NewReader(input), &out)
			if err != nil {
				t.Fatalf("unexpected optimistic auth error: %v", err)
			}
			if request == nil {
				t.Fatal("expected request after successful optimistic auth")
			}
			got := out.Bytes()
			wantPrefix := []byte{0x05, 0x02, 0x01, 0x00}
			if !bytes.HasPrefix(got, wantPrefix) {
				t.Fatalf("unexpected optimistic auth response: got % X, want prefix % X", got, wantPrefix)
			}
		})
	}
}
