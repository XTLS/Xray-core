package api

import "testing"

func TestSingleIndexFlagRejectsDuplicate(t *testing.T) {
	flag := &singleIndexFlag{value: -1}
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
		flag := &singleIndexFlag{value: -1}
		if err := flag.Set(value); err == nil {
			t.Errorf("expected index %q to be rejected", value)
		}
	}
}
