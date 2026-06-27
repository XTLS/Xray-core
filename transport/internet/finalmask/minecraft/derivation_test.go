package minecraft

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestDeriveRSAKey(t *testing.T) {
	password := "my-very-secret-password-12345"

	key1, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	err = key1.Validate()
	if err != nil {
		t.Fatalf("key is not valid RSA key: %v", err)
	}

	key2, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("failed to derive key second time: %v", err)
	}

	// Verify determinism
	if key1.D.Cmp(key2.D) != 0 || key1.N.Cmp(key2.N) != 0 {
		t.Errorf("derived keys are not identical for the same password")
	}

	// Verify different passwords yield different keys
	keyDifferent, err := DeriveRSAKey(password + "-different")
	if err != nil {
		t.Fatalf("failed to derive different key: %v", err)
	}

	if key1.D.Cmp(keyDifferent.D) == 0 || key1.N.Cmp(keyDifferent.N) == 0 {
		t.Errorf("derived keys are identical for different passwords")
	}
}

func TestDeriveRSAKeyGoldenPrivateKey(t *testing.T) {
	const password = "deterministic-rsa-key-golden"
	const wantPKCS1DERHash = "3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f"

	key, err := DeriveRSAKey(password)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	gotHash := sha256.Sum256(x509.MarshalPKCS1PrivateKey(key))
	got := hex.EncodeToString(gotHash[:])
	if got != wantPKCS1DERHash {
		t.Fatalf("derived private key changed\nwant sha256: %s\n got sha256: %s", wantPKCS1DERHash, got)
	}
}
