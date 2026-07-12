package api

import "testing"

func TestSingleIndexFlagRejectsDuplicate(t *testing.T) {
	flag := &singleIndexFlag{}
	if err := flag.Set("0"); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("1"); err == nil {
		t.Fatal("expected a repeated index to be rejected")
	}
	if flag.value != 0 {
		t.Fatalf("repeated index changed value to %d", flag.value)
	}
}

func TestSingleIndexFlagRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "invalid"} {
		flag := &singleIndexFlag{}
		if err := flag.Set(value); err == nil {
			t.Errorf("expected index %q to be rejected", value)
		}
		if flag.set {
			t.Errorf("invalid index %q marked the flag as explicitly set", value)
		}
	}
}

func TestSingleIndexFlagTracksExplicitZero(t *testing.T) {
	flag := &singleIndexFlag{}
	if flag.set {
		t.Fatal("new index flag must be unset")
	}
	if err := flag.Set("0"); err != nil {
		t.Fatal(err)
	}
	if !flag.set || flag.value != 0 {
		t.Fatalf("explicit zero was not preserved: %+v", flag)
	}
}
