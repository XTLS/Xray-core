package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/4nd3r5on/Xray-core/main/commands/base"
	"golang.org/x/crypto/curve25519"
)

var cmdX25519 = &base.Command{
	UsageLine: `{{.Exec}} x25519 [-i "private key (base64.RawURLEncoding)"] [--std-encoding]`,
	Short:     `Generate key pair for x25519 key exchange`,
	Long: `
Generate key pair for x25519 key exchange.

Random: {{.Exec}} x25519

From private key: {{.Exec}} x25519 -i "private key (base64.RawURLEncoding)"
For Std Encoding: {{.Exec}} x25519 --std-encoding
`,
}

func init() {
	cmdX25519.Run = executeX25519 // break init loop
}

var input_base64 = cmdX25519.Flag.String("i", "", "")
var input_stdEncoding = cmdX25519.Flag.Bool("std-encoding", false, "")

func executeX25519(cmd *base.Command, args []string) {
	var output string
	var err error
	var privateKey []byte
	var publicKey []byte
	var encoding *base64.Encoding
	if len(*input_base64) > 0 {
		privateKey, err = base64.RawURLEncoding.DecodeString(*input_base64)
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

	if *input_stdEncoding {
		encoding = base64.StdEncoding
	} else {
		encoding = base64.RawURLEncoding
	}

	output = fmt.Sprintf("Private key: %v\nPublic key: %v",
		encoding.EncodeToString(privateKey),
		encoding.EncodeToString(publicKey))
out:
	fmt.Println(output)
}
