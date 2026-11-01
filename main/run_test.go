package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunConfigCommands(t *testing.T) {
	if os.Getenv("XRAY_TEST_CONFIG_COMMAND") == "1" {
		os.Args = append([]string{os.Args[0]}, flag.Args()...)
		main()
		return
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	confdir := filepath.Join(dir, "conf.d")
	ignoredDir := filepath.Join(dir, "ignored")
	for _, path := range []string{confdir, ignoredDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	profile := filepath.Join(dir, "profile.json")
	script := filepath.Join(dir, "config.lua")
	binary := filepath.Join(dir, "config.pb")
	message := filepath.Join(dir, "user.tmsg")
	for path, body := range map[string]string{
		config:                                   "{}",
		profile:                                  `{"log":{"loglevel":"debug"}}`,
		filepath.Join(confdir, "10-common.json"): `{"log":{"loglevel":"warning"}}`,
		filepath.Join(confdir, "20-common.jsonc"): `{"log":{"loglevel":"error"}}`,
		filepath.Join(confdir, "30-ignored.yaml"): `{"log":{"loglevel":"info"}}`,
		filepath.Join(ignoredDir, "broken.json"):  "not a config",
		script:                                    "{}",
		binary:                                    "",
		message:                                   `{"type":"xray.app.dispatcher.Config","value":""}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Open(script)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, tc := range []struct {
		name  string
		args  []string
		code  int
		input io.Reader
		level string
	}{
		{"format override", []string{"run", "-test", "-format", "json", "-c", config}, 0, nil, ""},
		{"invalid extension", []string{"run", "-test", "-format", "json", "-c", script}, 23, nil, ""},
		{"default command", []string{"-test", "-format", "json", "-c", script}, 23, nil, ""},
		{"protobuf config", []string{"run", "-test", "-c", binary}, 0, nil, ""},
		{"protobuf error", []string{"run", "-test", "-format", "protobuf", "-c", script}, 23, nil, ""},
		{"merged source", []string{"run", "-test", "-format", "json", "-c", config, "-c", script}, 23, nil, ""},
		{"dump", []string{"run", "-dump", "-c", config}, 0, nil, ""},
		{"stdin pipe", []string{"run", "-test", "-c", "stdin:"}, 0, nil, ""},
		{"stdin file", []string{"run", "-test", "-c", "stdin:"}, 0, file, ""},
		{"convert json", []string{"convert", "json", message}, 0, nil, ""},
		{"convert pb", []string{"convert", "pb", "-debug", config}, 0, nil, ""},
		{"convert pb stdin", []string{"convert", "pb", "-debug", "stdin:"}, 0, file, ""},
		{"directory then file", []string{"run", "-dump", "-confdir", confdir, "-config", profile, "-format", "json"}, 0, nil, "debug"},
		{"file then directory", []string{"run", "-dump", "-config", profile, "-confdir", confdir, "-format", "json"}, 0, nil, "error"},
		{"interleaved aliases", []string{"run", "-dump", "-c", config, "--confdir=" + confdir, "-c=" + profile, "-format=json"}, 0, nil, "debug"},
		{"last directory wins", []string{"run", "-dump", "-confdir", ignoredDir, "-c", profile, "-confdir", confdir, "-format", "json"}, 0, nil, "error"},
		{"environment directory", []string{"run", "-dump", "-c", profile, "-format", "json"}, 0, nil, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestRunConfigCommands$", "--"}, tc.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "XRAY_TEST_CONFIG_COMMAND=1", "xray.location.confdir=", "XRAY_LOCATION_CONFDIR=")
			if tc.name == "environment directory" {
				cmd.Env = append(cmd.Env, "xray.location.confdir="+confdir)
			}
			cmd.Stdin = strings.NewReader("{}")
			if tc.input != nil {
				if _, err := file.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				cmd.Stdin = tc.input
			}
			output, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil {
				t.Fatal(err)
			}
			if code := cmd.ProcessState.ExitCode(); code != tc.code {
				t.Fatalf("exit code = %d, want %d: %v\n%s", code, tc.code, err, output)
			}
			if tc.level != "" {
				var merged struct{ Log struct{ Loglevel string } }
				if err := json.Unmarshal(output, &merged); err != nil {
					t.Fatalf("invalid merged config: %v\n%s", err, output)
				}
				if merged.Log.Loglevel != tc.level {
					t.Fatalf("loglevel = %q, want %q", merged.Log.Loglevel, tc.level)
				}
			}
			if tc.code == 23 && !strings.Contains(string(output), "failed to load config files") {
				t.Fatalf("missing config error:\n%s", output)
			}
		})
	}
}
