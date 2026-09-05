package conf

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func baseResponsePreludeConfig() SplitHTTPConfig {
	return SplitHTTPConfig{
		Mode:               "packet-up",
		Path:               "/test",
		SessionIDPlacement: splithttp.PlacementCookie,
		SeqPlacement:       splithttp.PlacementQuery,
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: splithttp.PlacementCookie,
			Key:       "sample_id",
			Table:     "Base62",
			Length:    Int32Range{From: 16, To: 32},
		},
	}
}

func TestResponsePreludeConfigBuildDefaults(t *testing.T) {
	cfg := SplitHTTPConfig{
		Mode:               "packet-up",
		Path:               "/test",
		SessionIDPlacement: splithttp.PlacementCookie,
		SeqPlacement:       splithttp.PlacementQuery,
		ResponsePrelude:    &ResponsePreludeConfig{},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	got := built.(*splithttp.Config).ResponsePrelude
	if got == nil {
		t.Fatal("internal response prelude config is nil")
	}
	if got.Placement != splithttp.PlacementCookie {
		t.Fatalf("placement: got %q", got.Placement)
	}
	if got.Key != "sample_id" {
		t.Fatalf("cookie key: got %q", got.Key)
	}
	if got.Table != splithttp.PredefinedTable["Base62"] {
		t.Fatal("table was not normalized to Base62")
	}
	if got.Length == nil || got.Length.From != 16 || got.Length.To != 32 {
		t.Fatalf("length: %#v", got.Length)
	}

	headerCfg := SplitHTTPConfig{
		Mode:               "packet-up",
		Path:               "/test",
		SessionIDPlacement: splithttp.PlacementCookie,
		SeqPlacement:       splithttp.PlacementQuery,
		ResponsePrelude: &ResponsePreludeConfig{
			Placement: splithttp.PlacementHeader,
		},
	}
	headerBuilt, err := headerCfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	headerGot := headerBuilt.(*splithttp.Config).ResponsePrelude
	if headerGot.Key != "X-Sample-ID" {
		t.Fatalf("header key: got %q", headerGot.Key)
	}
}

func TestResponsePreludeConfigBuildAllPlacements(t *testing.T) {
	tests := []struct {
		placement string
		key       string
	}{
		{splithttp.PlacementCookie, "pref_cookie"},
		{splithttp.PlacementHeader, "X-Pref"},
		{splithttp.PlacementQuery, "pref_query"},
		{splithttp.PlacementPath, ""},
	}

	for _, tt := range tests {
		t.Run(tt.placement, func(t *testing.T) {
			cfg := baseResponsePreludeConfig()
			cfg.ResponsePrelude.Placement = tt.placement
			cfg.ResponsePrelude.Key = tt.key
			built, err := cfg.Build()
			if err != nil {
				t.Fatal(err)
			}
			got := built.(*splithttp.Config).ResponsePrelude
			if got == nil || got.Placement != tt.placement {
				t.Fatalf("placement: %#v", got)
			}
		})
	}
}

func TestResponsePreludeConfigCustomTableAndFixedLength(t *testing.T) {
	cfg := baseResponsePreludeConfig()
	cfg.ResponsePrelude.Table = "abCD09-_"
	cfg.ResponsePrelude.Length = Int32Range{From: 24, To: 24}

	built, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	got := built.(*splithttp.Config).ResponsePrelude
	if got.Table != "abCD09-_" || got.Length.From != 24 || got.Length.To != 24 {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestResponsePreludeConfigRejectsInvalidPlacement(t *testing.T) {
	cfg := baseResponsePreludeConfig()
	cfg.ResponsePrelude.Placement = "body"

	_, err := cfg.Build()
	if err == nil || !strings.Contains(err.Error(), "unsupported responsePrelude placement") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResponsePreludeConfigRejectsPathConflicts(t *testing.T) {
	tests := []struct {
		name     string
		session  string
		sequence string
	}{
		{"session-path", splithttp.PlacementPath, splithttp.PlacementQuery},
		{"sequence-path", splithttp.PlacementCookie, splithttp.PlacementPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseResponsePreludeConfig()
			cfg.ResponsePrelude.Placement = splithttp.PlacementPath
			cfg.SessionIDPlacement = tt.session
			cfg.SeqPlacement = tt.sequence

			_, err := cfg.Build()
			if err == nil || !strings.Contains(err.Error(), "responsePrelude placement path") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResponsePreludeConfigRejectsInvalidTables(t *testing.T) {
	for _, table := range []string{"a", "ab/c", "ab c", "аб"} {
		t.Run(table, func(t *testing.T) {
			cfg := baseResponsePreludeConfig()
			cfg.ResponsePrelude.Table = table
			if _, err := cfg.Build(); err == nil {
				t.Fatalf("table %q unexpectedly accepted", table)
			}
		})
	}
}

func TestResponsePreludeConfigRejectsInvalidLengths(t *testing.T) {
	for _, length := range []Int32Range{
		{From: 0, To: 16},
		{From: 32, To: 16},
		{From: 1, To: splithttp.MaxResponsePreludeLength + 1},
	} {
		cfg := baseResponsePreludeConfig()
		cfg.ResponsePrelude.Length = length
		if _, err := cfg.Build(); err == nil {
			t.Fatalf("length %#v unexpectedly accepted", length)
		}
	}
}
