package outbound

import (
	goerrors "errors"
	"fmt"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/http2"
)

func TestIsHTTP2StreamReset(t *testing.T) {
	// Mirrors the reported symptom: a peer-initiated RST_STREAM surfacing as
	// StreamError{Code: INTERNAL_ERROR, Cause: "received from peer"}.
	peerReset := http2.StreamError{
		StreamID: 3,
		Code:     http2.ErrCodeInternal,
		Cause:    goerrors.New("received from peer"),
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"peer stream reset", peerReset, true},
		{"locally generated stream reset", http2.StreamError{StreamID: 5, Code: http2.ErrCodeCancel}, true},
		{"wrapped by xray errors", errors.New("failed to read packet length").Base(peerReset), true},
		{"wrapped by fmt.Errorf", fmt.Errorf("read: %w", peerReset), true},
		{"plain io.EOF", io.EOF, false},
		{"unrelated error", goerrors.New("boom"), false},
		{"nil", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHTTP2StreamReset(tc.err); got != tc.want {
				t.Errorf("isHTTP2StreamReset(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
