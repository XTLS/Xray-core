package main

import (
	"context"
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
	script := filepath.Join(dir, "config.lua")
	binary := filepath.Join(dir, "config.pb")
	message := filepath.Join(dir, "user.tmsg")
	for path, body := range map[string]string{
		config:  "{}",
		script:  "{}",
		binary:  "",
		message: `{"type":"xray.app.dispatcher.Config","value":""}`,
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
	}{
		{"format override", []string{"run", "-test", "-format", "json", "-c", config}, 0, nil},
		{"invalid extension", []string{"run", "-test", "-format", "json", "-c", script}, 23, nil},
		{"default command", []string{"-test", "-format", "json", "-c", script}, 23, nil},
		{"protobuf config", []string{"run", "-test", "-c", binary}, 0, nil},
		{"protobuf error", []string{"run", "-test", "-format", "protobuf", "-c", script}, 23, nil},
		{"merged source", []string{"run", "-test", "-format", "json", "-c", config, "-c", script}, 23, nil},
		{"dump", []string{"run", "-dump", "-c", config}, 0, nil},
		{"stdin pipe", []string{"run", "-test", "-c", "stdin:"}, 0, nil},
		{"stdin file", []string{"run", "-test", "-c", "stdin:"}, 0, file},
		{"convert json", []string{"convert", "json", message}, 0, nil},
		{"convert pb", []string{"convert", "pb", "-debug", config}, 0, nil},
		{"convert pb stdin", []string{"convert", "pb", "-debug", "stdin:"}, 0, file},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestRunConfigCommands$", "--"}, tc.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "XRAY_TEST_CONFIG_COMMAND=1")
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
			if tc.code == 23 && !strings.Contains(string(output), "failed to load config files") {
				t.Fatalf("missing config error:\n%s", output)
			}
		})
	}
}
