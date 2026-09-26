package tls

import (
	"slices"
	"sort"
	"testing"
)

func TestFingerprintSupportsTLS13(t *testing.T) {
	unsupported := make([]string, 0)
	for name := range PresetFingerprints {
		if name != "unsafe" && !FingerprintSupportsTLS13(name) {
			unsupported = append(unsupported, name)
		}
	}
	for name := range ModernFingerprints {
		if !FingerprintSupportsTLS13(name) {
			unsupported = append(unsupported, name)
		}
	}
	for name := range OtherFingerprints {
		if name != "hellogolang" && !FingerprintSupportsTLS13(name) {
			unsupported = append(unsupported, name)
		}
	}
	sort.Strings(unsupported)
	want := []string{
		"360",
		"android",
		"hello360_7_5",
		"hello360_auto",
		"helloandroid_11_okhttp",
		"hellochrome_58",
		"hellochrome_62",
		"hellofirefox_55",
		"hellofirefox_56",
		"helloios_11_1",
		"helloios_12_1",
		"hellorandomized",
		"hellorandomizedalpn",
		"hellorandomizednoalpn",
	}
	if !slices.Equal(unsupported, want) {
		t.Fatalf("unexpected TLS 1.2-only fingerprints: got %v, want %v", unsupported, want)
	}
}
