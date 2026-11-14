package conf

import (
	"encoding/json"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestFingerprintWeightsValidation(t *testing.T) {
	for name, weights := range map[string]FingerprintWeights{
		"nil": nil, "empty": {}, "zero": {"chrome": 0},
		"empty name": {"": 1}, "unknown": {"not-a-browser": 1},
		"duplicate": {"chrome": 1, "Chrome": 2},
		"overflow":  {"chrome": math.MaxUint64, "firefox": 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := weights.Validate(); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
	for _, name := range []string{"random", "unsafe", "hellogolang", "randomized", "randomizednoalpn", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn"} {
		t.Run(name, func(t *testing.T) {
			if err := (FingerprintWeights{name: 1}).Validate(); err == nil {
				t.Fatal("accepted non-browser or random mode")
			}
		})
	}
	for _, name := range []string{"chrome", "Firefox", "edge", "safari", "hellochrome_133", "hellofirefox_120"} {
		if err := (FingerprintWeights{name: math.MaxUint64}).Validate(); err != nil {
			t.Fatalf("valid fingerprint %s: %v", name, err)
		}
	}
}

func TestFingerprintWeightsJSON(t *testing.T) {
	for _, input := range []string{`{"chrome":-1}`, `{"chrome":1.5}`, `{"chrome":"1"}`, `{"chrome":18446744073709551616}`} {
		var w FingerprintWeights
		if err := json.Unmarshal([]byte(input), &w); err == nil {
			t.Fatalf("accepted invalid JSON weight: %s", input)
		}
	}
	var config struct {
		Weights FingerprintWeights `json:"fingerprintWeights"`
	}
	if err := json.Unmarshal([]byte(`{}`), &config); err != nil || config.Weights != nil {
		t.Fatalf("absent field: %+v, %v", config, err)
	}
	if err := json.Unmarshal([]byte(`{"fingerprintWeights":{}}`), &config); err != nil || config.Weights == nil {
		t.Fatalf("explicit empty field: %+v, %v", config, err)
	}
	if config.Weights.Validate() == nil {
		t.Fatal("accepted explicit empty policy")
	}
}

func TestFingerprintWeightsIntervals(t *testing.T) {
	p, err := (FingerprintWeights{"firefox": 9, "chrome": 70, "edge": 12, "safari": 9}).policy()
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for n := uint64(0); n < p.total; n++ {
		counts[p.pick(n)]++
	}
	for name, want := range map[string]int{"chrome": 70, "edge": 12, "firefox": 9, "safari": 9} {
		if counts[name] != want {
			t.Errorf("%s: %d intervals, want %d", name, counts[name], want)
		}
	}
	for n, want := range map[uint64]string{0: "chrome", 69: "chrome", 70: "edge", 81: "edge", 82: "firefox", 90: "firefox", 91: "safari", 99: "safari"} {
		if got := p.pick(n); got != want {
			t.Errorf("pick(%d) = %s, want %s", n, got, want)
		}
	}
}

func TestFingerprintWeightsProcessLifetime(t *testing.T) {
	var calls int
	r := fingerprintResolver{draw: func(total uint64) (uint64, error) {
		calls++
		return total - 1, nil
	}}
	policies := []FingerprintWeights{
		{"chrome": 70, "firefox": 30},
		{"FIREFOX": 3, "Chrome": 7},
		{"firefox": 60, "chrome": 140},
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(w FingerprintWeights) {
			defer wg.Done()
			name, err := r.resolve(w)
			if err != nil || name != "firefox" {
				t.Errorf("resolve = %q, %v", name, err)
			}
		}(policies[i%len(policies)])
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("selected %d times for equivalent policies", calls)
	}
	if _, err := r.resolve(FingerprintWeights{"chrome": 1, "firefox": 1}); err != nil || calls != 2 {
		t.Fatalf("distinct policy did not select independently: calls=%d, err=%v", calls, err)
	}
	// A new resolver models a new process and may choose a different profile.
	next := fingerprintResolver{draw: func(uint64) (uint64, error) { return 0, nil }}
	if name, err := next.resolve(policies[0]); err != nil || name != "chrome" {
		t.Fatalf("new process: %q, %v", name, err)
	}
}

func TestFingerprintWeightsSelectionFailure(t *testing.T) {
	sentinel := errors.New("entropy unavailable")
	calls := 0
	r := fingerprintResolver{draw: func(uint64) (uint64, error) {
		calls++
		if calls == 1 {
			return 0, sentinel
		}
		return 0, nil
	}}
	w := FingerprintWeights{"chrome": 1, "firefox": 1}
	if name, err := r.resolve(w); name != "" || !errors.Is(err, sentinel) || len(r.choices) != 0 {
		t.Fatalf("failure cached or hidden: %q, %v, %+v", name, err, r.choices)
	}
	if name, err := r.resolve(w); name != "chrome" || err != nil || calls != 2 {
		t.Fatalf("retry: %q, %v, calls=%d", name, err, calls)
	}
}

func TestFingerprintWeightsSingleCandidateAndValidation(t *testing.T) {
	r := fingerprintResolver{draw: func(uint64) (uint64, error) {
		t.Fatal("unexpected random selection")
		return 0, nil
	}}
	if name, err := r.resolve(FingerprintWeights{"Safari": 9}); name != "safari" || err != nil {
		t.Fatalf("single candidate: %q, %v", name, err)
	}
	if _, err := r.resolve(FingerprintWeights{"chrome": 1, "invalid": 1}); err == nil {
		t.Fatal("did not validate every candidate before selecting")
	}
	if len(r.choices) != 1 {
		t.Fatal("invalid policy was cached")
	}
	w := FingerprintWeights{"chrome": 1, "firefox": 2}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(r.choices) != 1 {
		t.Fatal("validation changed choices")
	}
}

func TestFingerprintWeightsResolvePreservesLegacyRandom(t *testing.T) {
	before := tls.GetFingerprint("random")
	w := FingerprintWeights{"chrome": 70, "firefox": 30}
	first, err := w.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	second, err := (FingerprintWeights{"Firefox": 3, "Chrome": 7}).Resolve()
	if err != nil || first != second || (first != "chrome" && first != "firefox") {
		t.Fatalf("process resolver: %q, %q, %v", first, second, err)
	}
	if tls.GetFingerprint("random") != before {
		t.Fatal("weighted selection changed legacy random")
	}
}
