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
	for len(code) != 0 {
		line, rest, _ := bytes.Cut(code, []byte{'\n'})
		code = rest
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		line, found := bytes.CutPrefix(bytes.TrimLeft(line, " \t"), []byte("--"))
		if !found {
			return false, nil
		}
		value, found := bytes.CutPrefix(bytes.TrimLeft(line, " \t"), []byte("@xray:privileged-signature="))
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
		digest := sha256.Sum256(bytes.TrimSpace(rest))
		if !ed25519.Verify(publicKey, digest[:], signature) {
			return false, errors.New("Lua privileged signature verification failed")
		}
		return true, nil
	}
	return false, nil
}
