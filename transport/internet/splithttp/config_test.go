package splithttp_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_GetNormalizedPath(t *testing.T) {
	tests := []struct {
		TestName           string
		Path               string
		SessionIDPlacement string
		SeqPlacement       string
		Expected           string
	}{
		{
			TestName: "default placement keeps trailing slash",
			Path:     "/sh",
			Expected: "/sh/",
		},
		{
			TestName: "query string is stripped",
			Path:     "/?world",
			Expected: "/",
		},
		{
			TestName:           "both off path drops trailing slash",
			Path:               "/stream",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/stream",
		},
		{
			TestName:           "both off path keeps file-like path",
			Path:               "/stream/filename.extension",
			SessionIDPlacement: "query",
			SeqPlacement:       "header",
			Expected:           "/stream/filename.extension",
		},
		{
			TestName:           "seq in path keeps trailing slash",
			Path:               "/stream",
			SessionIDPlacement: "query",
			Expected:           "/stream/",
		},
		{
			TestName:     "session in path keeps trailing slash",
			Path:         "/stream",
			SeqPlacement: "cookie",
			Expected:     "/stream/",
		},
		{
			TestName:           "existing trailing slash preserved",
			Path:               "/stream/",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/stream/",
		},
		{
			TestName:           "root unchanged",
			Path:               "/",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/",
		},
	}
	for _, test := range tests {
		t.Run(test.TestName, func(t *testing.T) {
			c := Config{
				Path:               test.Path,
				SessionIDPlacement: test.SessionIDPlacement,
				SeqPlacement:       test.SeqPlacement,
			}
			assert.Equal(t, test.Expected, c.GetNormalizedPath())
		})
	}
}

func Test_FillPacketRequest_GetBody(t *testing.T) {
	data := []byte("hello xray")
	payload := buf.MergeBytes(nil, data)

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	common.Must(err)

	config := &Config{}
	config.FillPacketRequest(req, "sess", "0", payload)

	if req.GetBody == nil {
		t.Fatalf("Expected GetBody to be set")
	}

	first, err := io.ReadAll(req.Body)
	common.Must(err)

	if string(data) != string(first) {
		t.Fatalf("Body mismatch. Format %q and %q are not equal", data, first)
	}

	body2, err := req.GetBody()
	common.Must(err)

	second, err := io.ReadAll(body2)
	common.Must(err)

	if string(data) != string(second) {
		t.Fatalf("Replayed body mismatch. Format %q and %q are not equal", data, second)
	}
}

func Test_GeneratePathSegment(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		c := Config{}
		assert.Equal(t, "", c.GeneratePathSegment("session"))
	})

	t.Run("stable for one session, different across sessions", func(t *testing.T) {
		c := Config{PathTable: "0123456789abcdef", PathLength: &RangeConfig{From: 12, To: 12}, PathExtension: ".js"}
		first := c.GeneratePathSegment("session-a")
		assert.Equal(t, first, c.GeneratePathSegment("session-a"))
		assert.NotEqual(t, first, c.GeneratePathSegment("session-b"))
	})

	t.Run("honours table, length and extension", func(t *testing.T) {
		c := Config{PathTable: "0123456789abcdef", PathLength: &RangeConfig{From: 8, To: 16}, PathExtension: ".js"}
		for _, sessionId := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			segment := c.GeneratePathSegment(sessionId)
			name := strings.TrimSuffix(segment, ".js")
			assert.True(t, strings.HasSuffix(segment, ".js"))
			assert.GreaterOrEqual(t, len(name), 8)
			assert.LessOrEqual(t, len(name), 16)
			for i := 0; i < len(name); i++ {
				assert.True(t, strings.IndexByte("0123456789abcdef", name[i]) >= 0)
			}
		}
	})

	t.Run("oversized table does not hang", func(t *testing.T) {
		table := strings.Repeat("abcdefghij", 30) // 300 characters
		c := Config{PathTable: table, PathLength: &RangeConfig{From: 8, To: 8}}
		assert.Len(t, c.GeneratePathSegment("session"), 8)
	})

	t.Run("random when there is no session id", func(t *testing.T) {
		c := Config{PathTable: "0123456789abcdef", PathLength: &RangeConfig{From: 16, To: 16}}
		assert.NotEqual(t, c.GeneratePathSegment(""), c.GeneratePathSegment(""))
	})
}

func Test_ApplyMetaToRequest_PathSegmentGoesLast(t *testing.T) {
	tests := []struct {
		TestName           string
		SessionIDPlacement string
		SeqPlacement       string
		ExpectedPrefix     string
	}{
		{
			TestName:           "session and seq in query",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			ExpectedPrefix:     "/assets/",
		},
		{
			TestName:       "session and seq in path",
			ExpectedPrefix: "/assets/sess/7/",
		},
	}
	for _, test := range tests {
		t.Run(test.TestName, func(t *testing.T) {
			c := Config{
				Path:               "/assets/",
				SessionIDPlacement: test.SessionIDPlacement,
				SeqPlacement:       test.SeqPlacement,
				PathTable:          "0123456789abcdef",
				PathLength:         &RangeConfig{From: 12, To: 12},
				PathExtension:      ".js",
			}
			req, err := http.NewRequest("GET", "https://example.com"+c.GetNormalizedPath(), nil)
			common.Must(err)
			c.ApplyMetaToRequest(req, "sess", "7")

			assert.True(t, strings.HasPrefix(req.URL.Path, test.ExpectedPrefix),
				"path %q does not start with %q", req.URL.Path, test.ExpectedPrefix)
			assert.True(t, strings.HasSuffix(req.URL.Path, ".js"))
			// The server matches on the configured prefix and ignores the rest.
			assert.True(t, strings.HasPrefix(req.URL.Path, c.GetNormalizedPath()))
		})
	}
}
