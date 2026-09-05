package splithttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/transport/internet/stat"
)

func testResponsePreludeConfig(placement string, table string, from, to int32) *Config {
	return &Config{
		SessionIDPlacement: PlacementCookie,
		SeqPlacement:       PlacementQuery,
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: placement,
			Key:       "pref",
			Table:     table,
			Length:    &RangeConfig{From: from, To: to},
		},
	}
}

func TestResponsePreludeRequestRoundTripAllPlacements(t *testing.T) {
	for _, placement := range []string{PlacementCookie, PlacementHeader, PlacementQuery, PlacementPath} {
		t.Run(placement, func(t *testing.T) {
			cfg := testResponsePreludeConfig(placement, PredefinedTable["Base62"], 16, 16)
			req, err := http.NewRequest(http.MethodGet, "https://example.com/stream", nil)
			if err != nil {
				t.Fatal(err)
			}

			value := cfg.GenerateResponsePrelude()
			if len(value) != 16 {
				t.Fatalf("unexpected response prelude length: %d", len(value))
			}

			cfg.ApplyResponsePreludeToRequest(req, value)
			got := cfg.ExtractResponsePreludeFromRequest(req, "/stream")
			if got != value {
				t.Fatalf("round trip mismatch: got %q want %q", got, value)
			}
			if !cfg.IsResponsePreludeValid(got) {
				t.Fatal("generated response prelude rejected")
			}
		})
	}
}

func TestResponsePreludeGenerationMatrix(t *testing.T) {
	tests := []struct {
		name  string
		table string
		from  int32
		to    int32
	}{
		{"base62-fixed", PredefinedTable["Base62"], 24, 24},
		{"base62-range", PredefinedTable["Base62"], 16, 32},
		{"custom-fixed", "abCD09-_", 8, 8},
		{"custom-range", "xyz789.~", 7, 19},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testResponsePreludeConfig(PlacementCookie, tt.table, tt.from, tt.to)
			seen := map[string]struct{}{}
			for i := 0; i < 256; i++ {
				value := cfg.GenerateResponsePrelude()
				if int32(len(value)) < tt.from || int32(len(value)) > tt.to {
					t.Fatalf("length %d outside %d..%d", len(value), tt.from, tt.to)
				}
				for _, ch := range value {
					if !strings.ContainsRune(tt.table, ch) {
						t.Fatalf("generated character %q outside table %q", ch, tt.table)
					}
				}
				if !cfg.IsResponsePreludeValid(value) {
					t.Fatalf("generated value rejected: %q", value)
				}
				seen[value] = struct{}{}
			}
			if len(seen) < 2 {
				t.Fatal("generator returned a constant value")
			}
		})
	}
}

func TestResponsePreludeDefaults(t *testing.T) {
	cfg := &Config{ResponsePrelude: &ResponsePreludeConfig{}}

	if got := cfg.GetNormalizedResponsePreludePlacement(); got != PlacementCookie {
		t.Fatalf("default placement: got %q want %q", got, PlacementCookie)
	}
	if got := cfg.GetNormalizedResponsePreludeKey(); got != "sample_id" {
		t.Fatalf("default cookie key: got %q", got)
	}
	if got := cfg.GetNormalizedResponsePreludeTable(); got != PredefinedTable["Base62"] {
		t.Fatal("default table is not Base62")
	}
	length := cfg.GetNormalizedResponsePreludeLength()
	if length == nil || length.From != 16 || length.To != 32 {
		t.Fatalf("default length: %#v", length)
	}

	cfg.ResponsePrelude.Placement = PlacementHeader
	cfg.ResponsePrelude.Key = ""
	if got := cfg.GetNormalizedResponsePreludeKey(); got != "X-Sample-ID" {
		t.Fatalf("default header key: got %q", got)
	}

	cfg.ResponsePrelude.Placement = PlacementQuery
	cfg.ResponsePrelude.Key = ""
	if got := cfg.GetNormalizedResponsePreludeKey(); got != "sample_id" {
		t.Fatalf("default query key: got %q", got)
	}
}

func TestResponsePreludeValidationRejectsBadValues(t *testing.T) {
	cfg := testResponsePreludeConfig(PlacementCookie, "abc", 3, 5)

	for _, value := range []string{"", "ab", "abcabc", "abZ"} {
		if cfg.IsResponsePreludeValid(value) {
			t.Fatalf("unexpected valid response prelude: %q", value)
		}
	}

	for _, value := range []string{"abc", "abcab", "caba"} {
		if !cfg.IsResponsePreludeValid(value) {
			t.Fatalf("unexpected invalid response prelude: %q", value)
		}
	}
}

func TestResponsePreludeDecisionMatrix(t *testing.T) {
	cfg := testResponsePreludeConfig(PlacementCookie, "abc", 3, 3)

	tests := []struct {
		name       string
		body       io.Reader
		uploadOnly bool
		want       bool
	}{
		{"stream-down", nil, false, true},
		{"stream-up-body", strings.NewReader("payload"), false, false},
		{"upload-only", nil, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldApplyResponsePrelude(cfg, tt.body, tt.uploadOnly); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}

	if shouldApplyResponsePrelude(&Config{}, nil, false) {
		t.Fatal("response prelude enabled without configuration")
	}
}

func TestResponsePreludeNeverAddedToPacketRequests(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, placement := range []string{PlacementCookie, PlacementHeader, PlacementQuery, PlacementPath} {
			t.Run(method+"-"+placement, func(t *testing.T) {
				cfg := testResponsePreludeConfig(placement, PredefinedTable["Base62"], 16, 32)
				cfg.UplinkHTTPMethod = method
				cfg.UplinkDataPlacement = PlacementBody
				cfg.XPaddingBytes = &RangeConfig{From: 1, To: 1}

				req, err := http.NewRequest(method, "https://example.com/upload", nil)
				if err != nil {
					t.Fatal(err)
				}

				if err := cfg.FillPacketRequest(req, "session123", "7", nil); err != nil {
					t.Fatal(err)
				}

				switch placement {
				case PlacementCookie:
					if cookie, err := req.Cookie("pref"); err == nil && cookie != nil {
						t.Fatalf("packet request unexpectedly has response prelude cookie: %q", cookie.Value)
					}
				case PlacementHeader:
					if got := req.Header.Get("pref"); got != "" {
						t.Fatalf("packet request unexpectedly has response prelude header: %q", got)
					}
				case PlacementQuery:
					if got := req.URL.Query().Get("pref"); got != "" {
						t.Fatalf("packet request unexpectedly has response prelude query: %q", got)
					}
				case PlacementPath:
					if strings.Contains(req.URL.Path, "/pref") {
						t.Fatalf("unexpected response prelude path: %q", req.URL.Path)
					}
					if req.URL.Path != "/upload" {
						t.Fatalf("packet request path changed unexpectedly: %q", req.URL.Path)
					}
				}
			})
		}
	}
}

func TestResponsePreludeReaderStripsMatch(t *testing.T) {
	reader := newResponsePreludeReadCloser(io.NopCloser(strings.NewReader("ABCpayload")), "ABC")
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Fatalf("got %q", got)
	}
}

func TestResponsePreludeReaderReplaysMismatch(t *testing.T) {
	reader := newResponsePreludeReadCloser(io.NopCloser(strings.NewReader("XYZpayload")), "ABC")
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "XYZpayload" {
		t.Fatalf("got %q", got)
	}
}

func TestResponsePreludeReaderReplaysShortSource(t *testing.T) {
	reader := newResponsePreludeReadCloser(io.NopCloser(strings.NewReader("AB")), "ABCD")
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "AB" {
		t.Fatalf("short source was not replayed: got %q", got)
	}
}

func TestResponsePreludeHandlerWritesPreludeBeforePayload(t *testing.T) {
	cfg := &Config{
		Mode: "stream-one",
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: PlacementCookie,
			Key:       "pref",
			Table:     PredefinedTable["Base62"],
			Length:    &RangeConfig{From: 16, To: 16},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.FillStreamRequest(req, "", "")
	prelude := cfg.GenerateResponsePrelude()
	cfg.ApplyResponsePreludeToRequest(req, prelude)

	h := &requestHandler{
		config: cfg,
		path:   "/stream",
		ln: &Listener{
			config: cfg,
			addConn: func(conn stat.Connection) {
				_ = conn.Close()
			},
		},
	}

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != prelude {
		t.Fatalf("response body: got %q want %q", body, prelude)
	}

	reader := newResponsePreludeReadCloser(io.NopCloser(strings.NewReader(string(body)+"payload")), prelude)
	stripped, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(stripped) != "payload" {
		t.Fatalf("response prelude was not stripped: got %q", stripped)
	}
}

func TestResponsePreludeHandlerRejectsInvalidValue(t *testing.T) {
	cfg := &Config{
		Mode: "stream-one",
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: PlacementHeader,
			Key:       "X-Test-Prelude",
			Table:     "abc",
			Length:    &RangeConfig{From: 3, To: 3},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/stream", nil)
	cfg.FillStreamRequest(req, "", "")
	req.Header.Set("X-Test-Prelude", "abZ")

	h := &requestHandler{
		config: cfg,
		path:   "/stream",
		ln: &Listener{
			config: cfg,
			addConn: func(conn stat.Connection) {
				_ = conn.Close()
			},
		},
	}

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got status %d want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestResponsePreludeAbsentPreservesLegacyBehavior(t *testing.T) {
	cfg := &Config{
		Mode: "stream-one",
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: PlacementCookie,
			Key:       "pref",
			Table:     PredefinedTable["Base62"],
			Length:    &RangeConfig{From: 16, To: 16},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/stream", nil)
	cfg.FillStreamRequest(req, "", "")

	h := &requestHandler{
		config: cfg,
		path:   "/stream",
		ln: &Listener{
			config: cfg,
			addConn: func(conn stat.Connection) {
				_ = conn.Close()
			},
		},
	}

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("legacy request unexpectedly received response prelude: %q", recorder.Body.String())
	}
}

func TestResponsePreludeCookieEnablesCORSCredentials(t *testing.T) {
	cfg := &Config{
		SessionIDPlacement:  PlacementPath,
		SeqPlacement:        PlacementPath,
		UplinkDataPlacement: PlacementBody,
		ResponsePrelude:     &ResponsePreludeConfig{Placement: PlacementCookie},
	}
	recorder := httptest.NewRecorder()
	cfg.WriteResponseHeader(recorder, http.MethodGet, http.Header{"Origin": []string{"https://example.com"}})
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials: got %q want true", got)
	}
}

func TestResponsePreludeNonCookieDoesNotForceCORSCredentials(t *testing.T) {
	cfg := &Config{
		SessionIDPlacement:  PlacementPath,
		SeqPlacement:        PlacementPath,
		UplinkDataPlacement: PlacementBody,
		ResponsePrelude:     &ResponsePreludeConfig{Placement: PlacementHeader},
	}
	recorder := httptest.NewRecorder()
	cfg.WriteResponseHeader(recorder, http.MethodGet, http.Header{"Origin": []string{"https://example.com"}})
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("unexpected Access-Control-Allow-Credentials: %q", got)
	}
}

func TestResponsePreludeInvalidMetadataIgnoredOnPacketUplink(t *testing.T) {
	cfg := &Config{
		Mode:                "packet-up",
		SessionIDPlacement:  PlacementCookie,
		SessionIDKey:        "x_session",
		SeqPlacement:        PlacementQuery,
		SeqKey:              "chunk_id",
		UplinkDataPlacement: PlacementBody,
		XPaddingBytes:       &RangeConfig{From: 1, To: 1},
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: PlacementHeader,
			Key:       "X-Test-Prelude",
			Table:     "abc",
			Length:    &RangeConfig{From: 3, To: 3},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.FillPacketRequest(req, "session123", "0", nil); err != nil {
		t.Fatal(err)
	}

	// Deliberately invalid for responsePrelude. Packet uplink must ignore it.
	req.Header.Set("X-Test-Prelude", "ZZZ")

	h := &requestHandler{
		config:    cfg,
		path:      "/stream",
		sessionMu: &sync.Mutex{},
		ln: &Listener{
			config: cfg,
		},
	}

	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("packet uplink unexpectedly rejected: got %d want %d", recorder.Code, http.StatusOK)
	}
}
