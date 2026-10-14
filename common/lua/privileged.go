package lua

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var privilegedKey struct {
	sync.Once
	publicKey ed25519.PublicKey
}

// SetPrivilegedPublicKey configures the trusted Ed25519 public key once at
// startup, before compiling scripts. An empty value disables authorization.
// Nonempty values must be unpadded Base64URL encodings of exactly 32 bytes.
func SetPrivilegedPublicKey(value string) error {
	var publicKey ed25519.PublicKey
	if value != "" {
		decoded, err := decodePrivilegedValue(value, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid Lua privileged public key").Base(err)
		}
		publicKey = ed25519.PublicKey(decoded)
	}
	privilegedKey.Do(func() {
		privilegedKey.publicKey = publicKey
	})
	return nil
}

func decodePrivilegedValue(value string, size int) ([]byte, error) {
	encoding := base64.RawURLEncoding.Strict()
	if len(value) != encoding.EncodedLen(size) {
		return nil, errors.New("expected an unpadded Base64URL encoding of ", size, " bytes")
	}
	decoded, err := encoding.DecodeString(value)
	if err != nil || len(decoded) != size || encoding.EncodeToString(decoded) != value {
		return nil, errors.New("expected an unpadded Base64URL encoding of ", size, " bytes")
	}
	return decoded, nil
}

func verifyPrivilegedSignature(code []byte) (bool, error) {
	_, end, value, found := privilegedSignatureLine(code)
	if !found {
		return false, nil
	}

	publicKey := privilegedKey.publicKey
	if len(publicKey) == 0 {
		return false, errors.New("Lua privileged signature requires --lua-privileged-pubkey")
	}
	signature, err := decodePrivilegedValue(string(bytes.TrimSpace(value)), ed25519.SignatureSize)
	if err != nil {
		return false, errors.New("invalid Lua privileged signature").Base(err)
	}
	digest := sha256.Sum256(bytes.TrimSpace(code[end:]))
	if !ed25519.Verify(publicKey, digest[:], signature) {
		return false, errors.New("Lua privileged signature verification failed")
	}
	return true, nil
}

// SignPrivilegedScript signs the script body, then prepends or replaces the signature line.
func SignPrivilegedScript(code []byte, seed string) ([]byte, error) {
	decoded, err := decodePrivilegedValue(seed, ed25519.SeedSize)
	if err != nil {
		return nil, errors.New("invalid Ed25519 private key seed").Base(err)
	}

	start, end, _, found := privilegedSignatureLine(code)
	body := code
	if found {
		body = code[end:]
	}

	digest := sha256.Sum256(bytes.TrimSpace(body))
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(decoded), digest[:])
	header := []byte("-- @xray:privileged-signature=" + base64.RawURLEncoding.EncodeToString(signature))

	if !found {
		if newline := bytes.IndexByte(code, '\n'); newline > 0 && code[newline-1] == '\r' {
			header = append(header, '\r')
		}
		header = append(header, '\n')
		return append(header, code...), nil
	}
	signed := make([]byte, 0, start+len(header)+len(code)-end)
	signed = append(signed, code[:start]...)
	signed = append(signed, header...)
	return append(signed, code[end:]...), nil
}

func privilegedSignatureLine(code []byte) (start, end int, value []byte, found bool) {
	for rest := code; len(rest) != 0; {
		start = len(code) - len(rest)
		var line []byte
		line, rest, _ = bytes.Cut(rest, []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		end = start + len(line)
		line, found := bytes.CutPrefix(bytes.TrimLeft(line, " \t"), []byte("--"))
		if !found {
			return 0, 0, nil, false
		}
		value, found = bytes.CutPrefix(bytes.TrimLeft(line, " \t"), []byte("@xray:privileged-signature="))
		return start, end, value, found
	}
	return 0, 0, nil, false
}
