package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func Curve25519Genkey(StdEncoding bool, input_base64 string) {
	var output string
	var err error
	var privateKey, publicKey []byte
	var encoding *base64.Encoding
	if *input_stdEncoding || StdEncoding {
		encoding = base64.StdEncoding
	} else {
		encoding = base64.RawURLEncoding
	}

	if len(input_base64) > 0 {
		privateKey, err = encoding.DecodeString(input_base64)
		if err != nil {
			output = err.Error()
			goto out
		}
		if len(privateKey) != curve25519.ScalarSize {
			output = "Invalid length of private key."
			goto out
		}
	}

	if privateKey == nil {
		privateKey = make([]byte, curve25519.ScalarSize)
		if _, err = rand.Read(privateKey); err != nil {
			output = err.Error()
			goto out
		}
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	if publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint); err != nil {
		output = err.Error()
		goto out
	}

	output = fmt.Sprintf("Private key: %v\nPublic key: %v",
		encoding.EncodeToString(privateKey),
		encoding.EncodeToString(publicKey))
out:
	fmt.Println(output)
}
