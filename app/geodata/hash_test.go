package geodata

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVerifyHashFile(t *testing.T) {
	dir := t.TempDir()
	data := []byte("geodata payload")
	dataFile := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dataFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)
	sumHex := hex.EncodeToString(sum[:])
	testCases := []string{
		sumHex + "\n",
		sumHex + "  geoip.dat\n",
		sumHex + "  *geoip.dat\n",
		sumHex + "  geosite.dat\n" + sumHex + "  geoip.dat\n",
		"SHA256 (geoip.dat) = " + sumHex + "\n",
	}

	for _, testCase := range testCases {
		hashFile := filepath.Join(dir, "geoip.dat.sha256sum")
		if err := os.WriteFile(hashFile, []byte(testCase), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyHashFile("sha-256", dataFile, hashFile, "geoip.dat"); err != nil {
			t.Fatalf("expected hash verification to pass for %q: %v", testCase, err)
		}
	}
}

func TestHashTypeDefault(t *testing.T) {
	dir := t.TempDir()
	data := []byte("geodata payload")
	dataFile := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dataFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)
	hashFile := filepath.Join(dir, "geoip.dat.sha256sum")
	if err := os.WriteFile(hashFile, []byte(hex.EncodeToString(sum[:])), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyHashFile("", dataFile, hashFile, "geoip.dat"); err != nil {
		t.Fatal(err)
	}

	hashType, err := NormalizeHashType("")
	if err != nil {
		t.Fatal(err)
	}
	if hashType != DefaultHashType {
		t.Fatalf("unexpected default hash type: %s", hashType)
	}
}

func TestSupportedHashTypes(t *testing.T) {
	testCases := []struct {
		input string
		want  string
		hash  crypto.Hash
	}{
		{input: "sha224", want: "sha224", hash: crypto.SHA224},
		{input: "sha-256", want: "sha256", hash: crypto.SHA256},
		{input: "SHA_384", want: "sha384", hash: crypto.SHA384},
		{input: "sha512", want: "sha512", hash: crypto.SHA512},
		{input: "sha512/224", want: "sha512/224", hash: crypto.SHA512_224},
		{input: "sha-512-256", want: "sha512/256", hash: crypto.SHA512_256},
		{input: "sha3-224", want: "sha3-224", hash: crypto.SHA3_224},
		{input: "sha3_256", want: "sha3-256", hash: crypto.SHA3_256},
		{input: "sha3384", want: "sha3-384", hash: crypto.SHA3_384},
		{input: "sha3-512", want: "sha3-512", hash: crypto.SHA3_512},
	}

	dir := t.TempDir()
	data := []byte("geodata payload")
	dataFile := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dataFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, testCase := range testCases {
		hashType, err := NormalizeHashType(testCase.input)
		if err != nil {
			t.Fatalf("expected %s to be supported: %v", testCase.input, err)
		}
		if hashType != testCase.want {
			t.Fatalf("unexpected normalized hash type for %s: got %s want %s", testCase.input, hashType, testCase.want)
		}
		if !testCase.hash.Available() {
			t.Fatalf("hash is not available: %s", testCase.want)
		}

		h := testCase.hash.New()
		_, _ = h.Write(data)
		hashFile := filepath.Join(dir, "geoip.dat."+strings.ReplaceAll(testCase.want, "/", "-")+".sum")
		if err := os.WriteFile(hashFile, []byte(hex.EncodeToString(h.Sum(nil))), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyHashFile(testCase.input, dataFile, hashFile, "geoip.dat"); err != nil {
			t.Fatalf("expected %s verification to pass: %v", testCase.input, err)
		}
	}
}

func TestWeakHashTypesAreRejected(t *testing.T) {
	for _, hashType := range []string{
		"md4",
		"md5",
		"sha1",
		"md5sha1",
		"ripemd160",
		"blake2s-256",
		"blake2b-256",
		"blake2b-384",
		"blake2b-512",
	} {
		if err := ValidateHashType(hashType); err == nil {
			t.Fatalf("expected %s to be rejected", hashType)
		}
	}
}

func TestVerifyHashFileMismatch(t *testing.T) {
	dir := t.TempDir()
	dataFile := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dataFile, []byte("geodata payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	wrongSum := sha256.Sum256([]byte("other payload"))
	hashFile := filepath.Join(dir, "geoip.dat.sha256sum")
	if err := os.WriteFile(hashFile, []byte(hex.EncodeToString(wrongSum[:])), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyHashFile("sha256", dataFile, hashFile, "geoip.dat"); err == nil {
		t.Fatal("expected hash verification to fail")
	}
}

func TestVerifyHashFileRejectsMismatchedFileName(t *testing.T) {
	dir := t.TempDir()
	data := []byte("geodata payload")
	dataFile := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dataFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)
	hashFile := filepath.Join(dir, "geoip.dat.sha256sum")
	if err := os.WriteFile(hashFile, []byte(hex.EncodeToString(sum[:])+"  geosite.dat\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := verifyHashFile("sha256", dataFile, hashFile, "geoip.dat"); err == nil {
		t.Fatal("expected hash verification to reject mismatched file name")
	}
}

func TestDownloadOneWithHash(t *testing.T) {
	data := []byte("new geodata payload")
	sum := sha256.Sum256(data)
	hashBody := []byte(hex.EncodeToString(sum[:]) + "  geoip.dat\n")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/geoip.dat":
			_, _ = writer.Write(data)
		case "/geoip.dat.sha256sum":
			_, _ = writer.Write(hashBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	dir := prepareDownloadAssetDir(t)
	downloader := &downloader{
		ctx:    context.Background(),
		client: server.Client(),
	}

	staged, err := downloader.downloadOne(&Asset{
		Url:      server.URL + "/geoip.dat",
		File:     "geoip.dat",
		HashUrl:  server.URL + "/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clean(staged)

	if len(staged) != 2 {
		t.Fatalf("expected 2 staged files, got %d", len(staged))
	}
	if staged[0].target != filepath.Join(dir, "geoip.dat") {
		t.Fatalf("unexpected asset target: %s", staged[0].target)
	}
	if staged[1].target != filepath.Join(dir, "geoip.dat.sha256sum") {
		t.Fatalf("unexpected hash target: %s", staged[1].target)
	}

	gotData, err := os.ReadFile(staged[0].temp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotData, data) {
		t.Fatalf("unexpected asset data: %q", gotData)
	}

	gotHash, err := os.ReadFile(staged[1].temp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHash, hashBody) {
		t.Fatalf("unexpected hash data: %q", gotHash)
	}
}

func TestDownloadOneSkipsAssetWhenHashUnchanged(t *testing.T) {
	data := []byte("remote geodata payload")
	localData := []byte("stale local geodata payload")
	sum := sha256.Sum256(data)
	hashBody := []byte(hex.EncodeToString(sum[:]) + "  geoip.dat\n")
	var assetRequested atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/geoip.dat":
			assetRequested.Store(true)
			http.Error(writer, "unexpected asset request", http.StatusInternalServerError)
		case "/geoip.dat.sha256sum":
			_, _ = writer.Write(hashBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	prepareDownloadAssetDirWith(t, localData, hashBody)
	downloader := &downloader{
		ctx:    context.Background(),
		client: server.Client(),
	}

	staged, err := downloader.downloadOne(&Asset{
		Url:      server.URL + "/geoip.dat",
		File:     "geoip.dat",
		HashUrl:  server.URL + "/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 0 {
		t.Fatalf("expected no staged files, got %d", len(staged))
	}
	if assetRequested.Load() {
		t.Fatal("asset was requested")
	}
}

func TestDownloadOneStagesOnlyHashWhenLocalHashMissing(t *testing.T) {
	data := []byte("current geodata payload")
	sum := sha256.Sum256(data)
	hashBody := []byte(hex.EncodeToString(sum[:]) + "  geoip.dat\n")
	var assetRequested atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/geoip.dat":
			assetRequested.Store(true)
			http.Error(writer, "unexpected asset request", http.StatusInternalServerError)
		case "/geoip.dat.sha256sum":
			_, _ = writer.Write(hashBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	dir := prepareDownloadAssetDirWith(t, data, hashBody)
	if err := os.Remove(filepath.Join(dir, "geoip.dat.sha256sum")); err != nil {
		t.Fatal(err)
	}
	downloader := &downloader{
		ctx:    context.Background(),
		client: server.Client(),
	}

	staged, err := downloader.downloadOne(&Asset{
		Url:      server.URL + "/geoip.dat",
		File:     "geoip.dat",
		HashUrl:  server.URL + "/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha256",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clean(staged)

	if len(staged) != 1 {
		t.Fatalf("expected only hash file to be staged, got %d", len(staged))
	}
	if staged[0].target != filepath.Join(dir, "geoip.dat.sha256sum") {
		t.Fatalf("unexpected hash target: %s", staged[0].target)
	}
	if assetRequested.Load() {
		t.Fatal("asset was requested")
	}
}

func TestDownloadOneDownloadsAssetWhenLocalHashDiffers(t *testing.T) {
	data := []byte("current geodata payload")
	sum := sha256.Sum256(data)
	hashBody := []byte(hex.EncodeToString(sum[:]) + "  geoip.dat\n")
	oldSum := sha256.Sum256([]byte("old geodata payload"))
	oldHashBody := []byte(hex.EncodeToString(oldSum[:]) + "  geoip.dat\n")
	var assetRequested atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/geoip.dat":
			assetRequested.Store(true)
			_, _ = writer.Write(data)
		case "/geoip.dat.sha256sum":
			_, _ = writer.Write(hashBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	dir := prepareDownloadAssetDirWith(t, data, oldHashBody)
	downloader := &downloader{
		ctx:    context.Background(),
		client: server.Client(),
	}

	staged, err := downloader.downloadOne(&Asset{
		Url:      server.URL + "/geoip.dat",
		File:     "geoip.dat",
		HashUrl:  server.URL + "/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha256",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clean(staged)

	if len(staged) != 2 {
		t.Fatalf("expected asset and hash files to be staged, got %d", len(staged))
	}
	if staged[0].target != filepath.Join(dir, "geoip.dat") {
		t.Fatalf("unexpected asset target: %s", staged[0].target)
	}
	if staged[1].target != filepath.Join(dir, "geoip.dat.sha256sum") {
		t.Fatalf("unexpected hash target: %s", staged[1].target)
	}
	if !assetRequested.Load() {
		t.Fatal("asset was not requested")
	}
}

func TestDownloadOneRejectsHashMismatch(t *testing.T) {
	data := []byte("new geodata payload")
	wrongSum := sha256.Sum256([]byte("other payload"))
	hashBody := []byte(hex.EncodeToString(wrongSum[:]) + "  geoip.dat\n")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/geoip.dat":
			_, _ = writer.Write(data)
		case "/geoip.dat.sha256sum":
			_, _ = writer.Write(hashBody)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	dir := prepareDownloadAssetDir(t)
	downloader := &downloader{
		ctx:    context.Background(),
		client: server.Client(),
	}

	_, err := downloader.downloadOne(&Asset{
		Url:      server.URL + "/geoip.dat",
		File:     "geoip.dat",
		HashUrl:  server.URL + "/geoip.dat.sha256sum",
		HashFile: "geoip.dat.sha256sum",
		HashType: "sha256",
	})
	if err == nil {
		t.Fatal("expected hash mismatch")
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("expected temp files to be cleaned, got %v", leftovers)
	}
}

func prepareDownloadAssetDir(t *testing.T) string {
	t.Helper()

	return prepareDownloadAssetDirWith(t, []byte("old geoip.dat"), []byte("old geoip.dat.sha256sum"))
}

func prepareDownloadAssetDirWith(t *testing.T, data []byte, hash []byte) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat.sha256sum"), hash, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("xray.location.asset", dir)
	return dir
}
