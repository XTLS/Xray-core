package splithttp

import (
	goerrors "errors"
	"io"
	"testing"

	"golang.org/x/net/http2"
)

type stubReadCloser struct{ err error }

func (r stubReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r stubReadCloser) Close() error             { return nil }

func TestSplitConnReadTranslatesH2StreamReset(t *testing.T) {
	// Peer-initiated reset carries http2's errFromPeer sentinel as Cause.
	peerReset := http2.StreamError{
		StreamID: 7,
		Code:     http2.ErrCodeInternal,
		Cause:    goerrors.New("received from peer"),
	}

	cases := []struct {
		name    string
		in      error
		wantEOF bool
	}{
		{"peer stream reset becomes EOF", peerReset, true},
		{"local stream reset becomes EOF", http2.StreamError{StreamID: 3, Code: http2.ErrCodeCancel}, true},
		{"wrapped stream reset becomes EOF", goerrors.Join(goerrors.New("read downlink"), peerReset), true},
		{"plain EOF passes through", io.EOF, true},
		{"unrelated error passes through unchanged", goerrors.New("boom"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &splitConn{reader: stubReadCloser{err: tc.in}}
			_, err := c.Read(make([]byte, 8))
			if tc.wantEOF && err != io.EOF {
				t.Fatalf("Read() err = %v, want io.EOF", err)
			}
			if !tc.wantEOF && err == io.EOF {
				t.Fatalf("Read() err = io.EOF, want passthrough of %v", tc.in)
			}
		})
	}
}
