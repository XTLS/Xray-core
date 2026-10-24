//go:build windows

package external

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReadConfigFileWindowsJunction(t *testing.T) {
	if path := os.Getenv("XRAY_TEST_CONFIG_JUNCTION"); path != "" {
		setCommandName(t, "run")
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		resolved, err := configFilePath(file)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Ext(resolved) != ".json" {
			t.Fatalf("configFilePath() = %q; want resolved .json target", resolved)
		}
		wantInfo, err := os.Stat(os.Getenv("XRAY_TEST_CONFIG_JUNCTION_TARGET"))
		if err != nil {
			t.Fatal(err)
		}
		gotInfo, err := os.Stat(resolved)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(wantInfo, gotInfo) {
			t.Fatalf("configFilePath() = %q; want the opened target", resolved)
		}
		content, err := readConfigFile(file)
		if err != nil || string(content) != "{}" {
			t.Fatalf("readConfigFile() = %q, %v; want {}, nil", content, err)
		}
		return
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	targetConfig := filepath.Join(target, "config.json")
	if err := os.WriteFile(targetConfig, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "cmd.exe", "/d", "/c", "mklink", "/J", junction, target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"relative from junction", "config.json"},
		{"absolute through junction", filepath.Join(junction, "config.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadConfigFileWindowsJunction$")
			command.Dir = junction
			command.Env = append(os.Environ(), "XRAY_TEST_CONFIG_JUNCTION="+tc.path, "XRAY_TEST_CONFIG_JUNCTION_TARGET="+targetConfig)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("read config from junction failed: %v\n%s", err, output)
			}
		})
	}
}

func TestConfigFilePathWindowsBufferGrowth(t *testing.T) {
	path := filepath.Join(t.TempDir(), strings.Repeat("a", 100)+".JSON")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	resolved, err := configFilePath(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) <= 100 || filepath.Ext(resolved) != ".JSON" {
		t.Fatalf("configFilePath() = %q; want complete target beyond initial buffer", resolved)
	}
	wantInfo, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	gotInfo, err := os.Stat(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(wantInfo, gotInfo) {
		t.Fatalf("configFilePath() = %q; want the opened file", resolved)
	}
}

func TestConfigFilePathWindowsClosedHandle(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if path, err := configFilePath(file); err == nil || path != "" {
		t.Fatalf("configFilePath() = %q, %v; want closed-handle error", path, err)
	}
}

func TestReadConfigFileWindowsSymlinkTarget(t *testing.T) {
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
			target := filepath.Join(dir, tc.target)
			if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(dir, tc.alias)
			if err := os.Symlink(target, alias); err != nil {
				if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
					t.Skip("file symlinks require Windows Developer Mode or symlink privilege")
				}
				t.Fatal(err)
			}
			file, err := os.Open(alias)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			resolved, err := configFilePath(file)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Ext(resolved) != filepath.Ext(target) {
				t.Fatalf("configFilePath() = %q; want target extension %q", resolved, filepath.Ext(target))
			}
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
