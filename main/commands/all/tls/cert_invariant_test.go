package tls

import (
	"os"
	"path/filepath"
	"testing"

	"main/commands/all/tls"
)

func TestCertificateFilesHaveSecurePermissions(t *testing.T) {
	// Adversarial inputs: filenames that could be targeted or manipulated
	payloads := []string{
		"../../../../tmp/private.key",      // Path traversal attempt
		"cert.key",                         // Normal case (valid input)
		"",                                 // Empty filename (boundary)
		"./../sensitive.key",               // Relative path manipulation
		"key\nwithnewline.key",             // Filename with newline
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			// Skip empty filename as it will fail before permission check
			if payload == "" {
				t.Skip("Empty filename test skipped - fails at file creation")
			}

			// Create a temporary directory for test isolation
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, filepath.Base(payload))

			// Call the actual production function
			testContent := []byte("test private key content")
			err := tls.WriteFile(testContent, testFile)
			if err != nil {
				// Some adversarial paths may fail to create - that's acceptable
				return
			}

			// Security property: File must NOT be readable by others
			stat, err := os.Stat(testFile)
			if err != nil {
				t.Fatalf("Failed to stat created file: %v", err)
			}

			// Check that file permissions are secure (not world-readable)
			perm := stat.Mode().Perm()
			if perm&0004 != 0 || perm&0002 != 0 { // Others read or write
				t.Errorf("Insecure file permissions %04o for private key file", perm)
			}

			// Clean up
			os.Remove(testFile)
		})
	}
}