package geodata

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/xtls/xray-core/common/errors"
)

const DefaultHashType = "sha256"

type hashSpec struct {
	name string
	hash crypto.Hash
}

func ValidateHashType(hashType string) error {
	_, err := hashSpecFor(hashType)
	return err
}

func NormalizeHashType(hashType string) (string, error) {
	spec, err := hashSpecFor(hashType)
	if err != nil {
		return "", err
	}
	return spec.name, nil
}

func hashSpecFor(hashType string) (hashSpec, error) {
	normalized := normalizeHashType(hashType)
	if normalized == "" {
		normalized = DefaultHashType
	}
	for _, spec := range supportedHashSpecs {
		if slices.Contains(spec.aliases, normalized) {
			return hashSpec{
				name: spec.name,
				hash: spec.hash,
			}, nil
		}
	}
	return hashSpec{}, errors.New("unsupported geodata hash type: ", hashType)
}

func normalizeHashType(hashType string) string {
	hashType = strings.ToLower(strings.TrimSpace(hashType))
	hashType = strings.ReplaceAll(hashType, "-", "")
	hashType = strings.ReplaceAll(hashType, "_", "")
	hashType = strings.ReplaceAll(hashType, "/", "")
	return hashType
}

type hashSpecDef struct {
	name    string
	hash    crypto.Hash
	aliases []string
}

var supportedHashSpecs = []hashSpecDef{
	{name: "sha224", hash: crypto.SHA224, aliases: []string{"sha224"}},
	{name: "sha256", hash: crypto.SHA256, aliases: []string{"sha256"}},
	{name: "sha384", hash: crypto.SHA384, aliases: []string{"sha384"}},
	{name: "sha512", hash: crypto.SHA512, aliases: []string{"sha512"}},
	{name: "sha512/224", hash: crypto.SHA512_224, aliases: []string{"sha512224"}},
	{name: "sha512/256", hash: crypto.SHA512_256, aliases: []string{"sha512256"}},
	{name: "sha3-224", hash: crypto.SHA3_224, aliases: []string{"sha3224"}},
	{name: "sha3-256", hash: crypto.SHA3_256, aliases: []string{"sha3256"}},
	{name: "sha3-384", hash: crypto.SHA3_384, aliases: []string{"sha3384"}},
	{name: "sha3-512", hash: crypto.SHA3_512, aliases: []string{"sha3512"}},
}

func verifyHashFile(hashType string, dataFile string, hashFile string, expectedFile string) error {
	spec, err := hashSpecFor(hashType)
	if err != nil {
		return err
	}

	expected, err := readHashFileDigestWithSpec(hashFile, spec, expectedFile)
	if err != nil {
		return err
	}

	actual, err := computeFileHash(dataFile, spec)
	if err != nil {
		return errors.New("failed to compute geodata asset hash").Base(err)
	}

	if !bytes.Equal(expected, actual) {
		return errors.New(
			"geodata asset hash mismatch for ", dataFile,
			": expected ", hex.EncodeToString(expected),
			", actual ", hex.EncodeToString(actual),
		)
	}
	return nil
}

func readHashFileDigest(hashType string, file string, expectedFile string) ([]byte, error) {
	spec, err := hashSpecFor(hashType)
	if err != nil {
		return nil, err
	}
	return readHashFileDigestWithSpec(file, spec, expectedFile)
}

func computeFileHash(file string, spec hashSpec) ([]byte, error) {
	reader, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	h := spec.hash.New()
	if _, err := io.Copy(h, reader); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func readHashFileDigestWithSpec(file string, spec hashSpec, expectedFile string) ([]byte, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("failed to read geodata hash file").Base(err)
	}

	wantHexLen := spec.hash.Size() * 2
	for line := range strings.SplitSeq(string(content), "\n") {
		digest, fileName, hasFileName, ok := parseHashLine(line, wantHexLen)
		if !ok {
			continue
		}
		if hasFileName && !hashFileNameMatches(fileName, expectedFile) {
			continue
		}

		expected, err := hex.DecodeString(digest)
		if err != nil {
			return nil, errors.New("failed to decode geodata hash file").Base(err)
		}
		return expected, nil
	}

	return nil, errors.New("geodata hash file does not contain a ", spec.name, " hex digest")
}

func parseHashLine(line string, wantHexLen int) (digest string, fileName string, hasFileName bool, ok bool) {
	fields := strings.Fields(line)
	for i, field := range fields {
		token := normalizeHashToken(field)
		if len(token) != wantHexLen || !isHexString(token) {
			continue
		}

		if name, found := extractBSDChecksumFileName(line); found {
			return token, name, true, true
		}
		if i == 0 && len(fields) > 1 {
			return token, fields[1], true, true
		}
		return token, "", false, true
	}
	return "", "", false, false
}

func extractBSDChecksumFileName(line string) (string, bool) {
	start := strings.IndexByte(line, '(')
	end := strings.LastIndexByte(line, ')')
	if start < 0 || end <= start {
		return "", false
	}
	return line[start+1 : end], true
}

func hashFileNameMatches(actual string, expected string) bool {
	actual = normalizeHashFileName(actual)
	expected = normalizeHashFileName(expected)
	if expected == "" {
		return true
	}
	if actual == "" {
		return false
	}
	return actual == expected || path.Base(actual) == path.Base(expected)
}

func normalizeHashFileName(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	fileName = strings.TrimPrefix(fileName, "*")
	fileName = strings.Trim(fileName, "\"'")
	fileName = strings.ReplaceAll(fileName, "\\", "/")
	fileName = strings.TrimPrefix(fileName, "./")
	fileName = path.Clean(fileName)
	if fileName == "." {
		return ""
	}
	return fileName
}

func normalizeHashToken(token string) string {
	token = strings.TrimFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("*()=[]{}<>:,;\"'", r)
	})
	token = strings.TrimPrefix(strings.ToLower(token), "0x")
	token = strings.ReplaceAll(token, ":", "")
	return token
}

func isHexString(s string) bool {
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
