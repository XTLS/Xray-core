package http

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestReadResponseAndHandle100ContinueShortLine(t *testing.T) {
	// A malformed upstream "1xx" response whose first header line is shorter
	// than 4 bytes used to slice out of range and panic. responseDone runs in
	// a goroutine without recover, so the panic crashed the whole process.
	// The leading space makes strings.Cut classify the status as "1...".
	input := " 1\n" + strings.Repeat("X", 80)
	r := bufio.NewReader(strings.NewReader(input))
	if _, err := readResponseAndHandle100Continue(r, nil, io.Discard); err == nil {
		t.Error("expected an error, got nil")
	}
}
