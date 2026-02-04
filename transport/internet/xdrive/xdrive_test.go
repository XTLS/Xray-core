package xdrive_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/xtls/xray-core/transport/internet/xdrive"
)

func TestLocalDriveService(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := filepath.Join(os.TempDir(), "xdrive_test")
	defer os.RemoveAll(tmpDir)

	service := NewLocalDriveService(tmpDir)
	ctx := context.Background()

	// Test Login (creates directory)
	if err := service.Login(ctx); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test Upload
	testData := []byte("hello world")
	testFileName := "test-file-1"
	if err := service.Upload(ctx, testFileName, testData); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	// Test List
	files, err := service.List(ctx, "test-", 10*time.Second)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Expected 1 file, got %d", len(files))
	}
	if files[0].Name != testFileName {
		t.Fatalf("Expected file name %s, got %s", testFileName, files[0].Name)
	}

	// Test Download
	downloaded, err := service.Download(ctx, testFileName)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if string(downloaded) != string(testData) {
		t.Fatalf("Downloaded data mismatch: expected %s, got %s", string(testData), string(downloaded))
	}

	// Test Delete
	if err := service.Delete(ctx, testFileName); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify file is deleted
	files, err = service.List(ctx, "test-", 10*time.Second)
	if err != nil {
		t.Fatalf("List after delete failed: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("Expected 0 files after delete, got %d", len(files))
	}
}

func TestFileNameParsing(t *testing.T) {
	// Test valid filename
	sessionID := "550e8400-e29b-41d4-a716-446655440000"
	fileName := sessionID + "-up-5"

	parsed, direction, seq, ok := ParseFileName(fileName)
	if !ok {
		t.Fatalf("Failed to parse valid filename")
	}
	if parsed != sessionID {
		t.Fatalf("Session ID mismatch: expected %s, got %s", sessionID, parsed)
	}
	if direction != "up" {
		t.Fatalf("Direction mismatch: expected up, got %s", direction)
	}
	if seq != 5 {
		t.Fatalf("Seq mismatch: expected 5, got %d", seq)
	}

	// Test invalid filenames
	invalidNames := []string{
		"invalid-file",
		"550e8400-e29b-41d4-a716-446655440000-invalid-5",
		"not-a-uuid-up-5",
	}
	for _, name := range invalidNames {
		_, _, _, ok := ParseFileName(name)
		if ok {
			t.Fatalf("Expected parsing to fail for %s", name)
		}
	}
}

func TestMakeFileName(t *testing.T) {
	sessionID := "550e8400-e29b-41d4-a716-446655440000"
	expected := "550e8400-e29b-41d4-a716-446655440000-down-10"
	result := MakeFileName(sessionID, "down", 10)
	if result != expected {
		t.Fatalf("MakeFileName mismatch: expected %s, got %s", expected, result)
	}
}
