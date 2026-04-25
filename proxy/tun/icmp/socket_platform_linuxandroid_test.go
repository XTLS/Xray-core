//go:build linux || android

package icmp

import (
	stderrors "errors"
	"testing"
)

func TestIsPermissionError(t *testing.T) {
	if !isPermissionError(stderrors.New("socket: permission denied")) {
		t.Fatal("expected permission denied to be recognized")
	}
	if !isPermissionError(stderrors.New("listen ip4:icmp 0.0.0.0: socket: operation not permitted")) {
		t.Fatal("expected operation not permitted to be recognized")
	}
	if isPermissionError(stderrors.New("i/o timeout")) {
		t.Fatal("did not expect timeout to be recognized as permission issue")
	}
}
