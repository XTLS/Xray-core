//go:build !windows

package external

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigFileSymlinkTarget(t *testing.T) {
	setCommandName(t, "run")
	for _, tc := range []struct {
		name   string
		target string
		alias  string
		reject bool
	}{
		{"rejected target", "target.lua", "alias.json", true},
		{"allowed target", "target.JSON", "alias.lua", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.target), []byte("content"), 0o600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(dir, tc.alias)
			if err := os.Symlink(tc.target, alias); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(alias)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got, err := readConfigFile(file)
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "unsupported config file extension") || len(got) != 0 {
					t.Fatalf("readConfigFile() = %q, %v; want rejected target", got, err)
				}
			} else if err != nil || string(got) != "content" {
				t.Fatalf("readConfigFile() = %q, %v; want content, nil", got, err)
			}
		})
	}
}
