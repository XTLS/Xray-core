package tls

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadFromFiles(t *testing.T) {
	dir := t.TempDir()
	entry := &Certificate{
		CertificatePath: filepath.Join(dir, "cert.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		Certificate:     []byte("cert-1"),
		Key:             []byte("key-1"),
	}
	writeFiles := func(cert, key string) {
		t.Helper()
		if err := os.WriteFile(entry.CertificatePath, []byte(cert), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entry.KeyPath, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name string, wantReloaded, wantErr bool, wantCert, wantKey string) {
		t.Helper()
		reloaded, err := reloadFromFiles(entry)
		if reloaded != wantReloaded || (err != nil) != wantErr {
			t.Fatalf("%s: got reloaded=%v, err=%v", name, reloaded, err)
		}
		if string(entry.Certificate) != wantCert || string(entry.Key) != wantKey {
			t.Fatalf("%s: got cert=%q, key=%q", name, entry.Certificate, entry.Key)
		}
	}

	writeFiles("cert-1", "key-1")
	check("unchanged", false, false, "cert-1", "key-1")

	if err := os.Remove(entry.CertificatePath); err != nil {
		t.Fatal(err)
	}
	check("missing certificate", false, true, "cert-1", "key-1")

	writeFiles("cert-2", "key-2")
	check("changed", true, false, "cert-2", "key-2")
}
