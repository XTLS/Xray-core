package external

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/main/commands/base"
)

func setCommandName(t *testing.T, name string) {
	t.Helper()
	original := base.CommandEnv.CommandName
	base.CommandEnv.CommandName = name
	t.Cleanup(func() { base.CommandEnv.CommandName = original })
}

func TestReadConfigFileExtensions(t *testing.T) {
	setCommandName(t, "run")
	for _, extension := range []string{".jsonc", ".json", ".yml", ".yaml", ".toml", ".pb", ".protobuf", ".JSON", ".lua", ".txt", ""} {
		t.Run("config"+extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config"+extension)
			content := []byte("configuration bytes")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got, err := readConfigFile(file)
			if extension == ".lua" || extension == ".txt" || extension == "" {
				if err == nil || !strings.Contains(err.Error(), "unsupported config file extension") {
					t.Fatalf("readConfigFile() = %q, %v; want unsupported extension", got, err)
				}
				if len(got) != 0 {
					t.Fatalf("readConfigFile() returned rejected content: %q", got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, content) {
				t.Fatalf("readConfigFile() = %q, %v; want %q, nil", got, err, content)
			}
		})
	}
}

func TestReadConfigFileOtherCommand(t *testing.T) {
	setCommandName(t, "version")
	path := filepath.Join(t.TempDir(), "config.lua")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := readConfigFile(file)
	if err != nil || string(got) != "content" {
		t.Fatalf("readConfigFile() = %q, %v; want content, nil", got, err)
	}
}

func TestReadConfigFilePipe(t *testing.T) {
	setCommandName(t, "run")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := writer.Write([]byte("pipe content")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readConfigFile(reader)
	if err != nil || string(got) != "pipe content" {
		t.Fatalf("readConfigFile() = %q, %v; want pipe content, nil", got, err)
	}
}
