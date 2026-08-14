package geodata

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

func TestShouldUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)

	path := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	schedule, err := cron.ParseStandard("0 4 * * *")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.Local)
	instance := &Instance{
		assets:     []*Asset{{File: "geoip.dat"}},
		downloader: &downloader{},
		schedule:   schedule,
	}

	for _, test := range []struct {
		name    string
		modTime time.Time
		want    bool
	}{
		{
			name:    "before scheduled update",
			modTime: time.Date(2026, time.August, 14, 3, 59, 0, 0, time.Local),
			want:    true,
		},
		{
			name:    "previous day",
			modTime: time.Date(2026, time.August, 13, 4, 1, 0, 0, time.Local),
			want:    true,
		},
		{
			name:    "after scheduled update",
			modTime: time.Date(2026, time.August, 14, 4, 1, 0, 0, time.Local),
			want:    false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chtimes(path, test.modTime, test.modTime); err != nil {
				t.Fatal(err)
			}
			if got := instance.shouldUpdate(now); got != test.want {
				t.Fatalf("shouldUpdate() = %t, want %t", got, test.want)
			}
		})
	}
}
