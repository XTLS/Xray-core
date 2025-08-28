package all

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"lukechampine.com/blake3"
)

func Curve25519Genkey(StdEncoding bool, input_base64 string) {
	var encoding *base64.Encoding
	if *input_stdEncoding || StdEncoding {
		encoding = base64.StdEncoding
	} else {
		encoding = base64.RawURLEncoding
	}

	var privateKey []byte
	if len(input_base64) > 0 {
		privateKey, _ = encoding.DecodeString(input_base64)
		if len(privateKey) != 32 {
			fmt.Println("Invalid length of X25519 private key.")
			return
		}
	}
	if privateKey == nil {
		privateKey = make([]byte, 32)
		rand.Read(privateKey)
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html
	// (Just to make sure printing the real private key)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	password := key.PublicKey().Bytes()
	hash32 := blake3.Sum256(password)
	fmt.Printf("PrivateKey: %v\nPassword: %v\nHash32: %v",
		encoding.EncodeToString(privateKey),
		encoding.EncodeToString(password),
		encoding.EncodeToString(hash32[:]))
}
