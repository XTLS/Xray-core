package splithttp

import (
	"regexp"
	"testing"
)

func TestNewSessionIDFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		pattern string
	}{
		{
			name:    "default",
			format:  "",
			pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
		},
		{
			name:    "uuid",
			format:  SessionIdFormatUUID,
			pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
		},
		{
			name:    "random hex",
			format:  SessionIdFormatRandomHex,
			pattern: `^[0-9a-f]{32}$`,
		},
		{
			name:    "random base62",
			format:  SessionIdFormatRandomBase62,
			pattern: `^[0-9A-Za-z]{22}$`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessionID := newSessionID(test.format)
			if !regexp.MustCompile(test.pattern).MatchString(sessionID) {
				t.Fatalf("session id %q does not match %q", sessionID, test.pattern)
			}
		})
	}
}
