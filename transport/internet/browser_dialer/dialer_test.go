package browser_dialer

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestBrowserDialerPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is unavailable; run node --test dialer_test.mjs to test the browser page")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, node, "--test", "dialer_test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("Browser Dialer JavaScript tests: %v\n%s", err, output)
	}
}
