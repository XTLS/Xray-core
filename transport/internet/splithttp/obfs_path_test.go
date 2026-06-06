package splithttp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecorateRequestPath(t *testing.T) {
	// No pool: the path is left untouched.
	c := &Config{}
	req := httptest.NewRequest("GET", "https://example.com/api/v1/", nil)
	c.DecorateRequestPath(req)
	if req.URL.Path != "/api/v1/" {
		t.Fatalf("empty pool changed the path: %q", req.URL.Path)
	}

	// With a pool: append one entry, keep the base prefix, expand "*".
	c = &Config{PathPool: []string{"timeline", "items/*"}}
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "https://example.com/api/v1/", nil)
		c.DecorateRequestPath(req)
		rest, ok := strings.CutPrefix(req.URL.Path, "/api/v1/")
		if !ok {
			t.Fatalf("lost the base prefix: %q", req.URL.Path)
		}
		if strings.Contains(rest, "*") {
			t.Fatalf("star was not expanded: %q", rest)
		}
		if rest != "timeline" && !strings.HasPrefix(rest, "items/") {
			t.Fatalf("unexpected segment: %q", rest)
		}
	}
}
