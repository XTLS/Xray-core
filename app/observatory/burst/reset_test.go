package burst

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMatchTag(t *testing.T) {
	tags, prefixes := []string{"cf_22", "f_7"}, []string{"gc_", ""}
	cases := map[string]bool{
		"cf_22":  true,
		"cf_220": false,
		"f_7":    true,
		"f_70":   false,
		"gc_1":   true,
		"aws_1":  false,
	}
	for tag, want := range cases {
		if got := matchTag(tag, tags, prefixes); got != want {
			t.Errorf("matchTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

func TestResetResults(t *testing.T) {
	h := NewHealthPing(context.Background(), nil, &HealthPingConfig{
		Interval:      int64(time.Minute),
		SamplingCount: 4,
	})
	for _, tag := range []string{"cf_1", "cf_2", "cf_22", "f_1", "gc_1"} {
		h.PutResult(tag, 100*time.Millisecond)
	}
	h.persistPath = filepath.Join(t.TempDir(), persistFileName)

	got := h.ResetResults([]string{"f_1", "nope"}, []string{"cf_2"})
	if want := []string{"cf_2", "cf_22", "f_1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cleared %v, want %v", got, want)
	}
	h.access.Lock()
	left := make([]string, 0, len(h.Results))
	for tag := range h.Results {
		left = append(left, tag)
	}
	h.access.Unlock()
	if len(left) != 2 || h.Results["cf_1"] == nil || h.Results["gc_1"] == nil {
		t.Errorf("results left %v, want cf_1 and gc_1", left)
	}

	// the state file is rewritten at once without the cleared outbounds
	b, err := os.ReadFile(h.persistPath)
	if err != nil {
		t.Fatal(err)
	}
	var data persistData
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Observatory) != 2 || data.Observatory["cf_2"] != nil {
		t.Errorf("saved outbounds %v, want cf_1 and gc_1", data.Observatory)
	}

	if got := h.ResetResults(nil, []string{"zz_"}); len(got) != 0 {
		t.Errorf("cleared %v, want nothing", got)
	}
}
