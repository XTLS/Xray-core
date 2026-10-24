package splithttp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
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

func Test_SetResponseHeader(t *testing.T) {
	defaults := map[string]string{
		"Access-Control-Allow-Origin": "*",
		"X-Accel-Buffering":           "no",
		"Cache-Control":               "no-store",
	}

	t.Run("default without responseHeaders", func(t *testing.T) {
		c := &Config{}
		header := http.Header{}
		for key, value := range defaults {
			c.SetResponseHeader(header, key, value)
			assert.Equal(t, value, header.Get(key))
		}
	})

	t.Run("override default value", func(t *testing.T) {
		c := &Config{ResponseHeaders: map[string]string{"Cache-Control": "no-cache, no-transform"}}
		header := http.Header{}
		c.SetResponseHeader(header, "Cache-Control", "no-store")
		assert.Equal(t, "no-cache, no-transform", header.Get("Cache-Control"))
	})

	t.Run("remove default with empty value", func(t *testing.T) {
		c := &Config{ResponseHeaders: map[string]string{"X-Accel-Buffering": ""}}
		header := http.Header{}
		c.SetResponseHeader(header, "X-Accel-Buffering", "no")
		_, exists := header["X-Accel-Buffering"]
		assert.False(t, exists)
	})
}

func Test_WriteResponseHeader_ResponseHeaders(t *testing.T) {
	t.Run("CORS header is set by default", func(t *testing.T) {
		c := &Config{}
		recorder := httptest.NewRecorder()
		c.WriteResponseHeader(recorder, http.MethodGet, http.Header{})
		assert.Equal(t, "*", recorder.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS header can be overridden", func(t *testing.T) {
		c := &Config{ResponseHeaders: map[string]string{"Access-Control-Allow-Origin": "https://example.com"}}
		recorder := httptest.NewRecorder()
		c.WriteResponseHeader(recorder, http.MethodGet, http.Header{})
		assert.Equal(t, "https://example.com", recorder.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS header can be removed", func(t *testing.T) {
		c := &Config{ResponseHeaders: map[string]string{"Access-Control-Allow-Origin": ""}}
		recorder := httptest.NewRecorder()
		c.WriteResponseHeader(recorder, http.MethodGet, http.Header{})
		_, exists := recorder.Header()["Access-Control-Allow-Origin"]
		assert.False(t, exists)
	})

	t.Run("custom header is added", func(t *testing.T) {
		c := &Config{ResponseHeaders: map[string]string{"Server": "nginx"}}
		recorder := httptest.NewRecorder()
		c.WriteResponseHeader(recorder, http.MethodGet, http.Header{})
		assert.Equal(t, "nginx", recorder.Header().Get("Server"))
	})

	t.Run("origin is echoed by default", func(t *testing.T) {
		c := &Config{}
		recorder := httptest.NewRecorder()
		requestHeader := http.Header{"Origin": {"https://origin.example.com"}}
		c.WriteResponseHeader(recorder, http.MethodGet, requestHeader)
		assert.Equal(t, "https://origin.example.com", recorder.Header().Get("Access-Control-Allow-Origin"))
	})
}
