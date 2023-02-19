package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/xtls/xray-core/main/commands/base"
	"golang.org/x/crypto/curve25519"
)

var cmdX25519 = &base.Command{
	UsageLine: `{{.Exec}} x25519 [-i "private key (base64.RawURLEncoding)"]`,
	Short:     `Generate key pair for x25519 key exchange`,
	Long: `
Generate key pair for x25519 key exchange.

Random: {{.Exec}} x25519

From private key: {{.Exec}} x25519 -i "private key (base64.RawURLEncoding)"
`,
}

func init() {
	cmdX25519.Run = executeX25519 // break init loop
}

var input_base64 = cmdX25519.Flag.String("i", "", "")

func executeX25519(cmd *base.Command, args []string) {
	var output string
	var err error
	var privateKey []byte
	var publicKey []byte
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
		if _, err = io.ReadFull(rand.Reader, privateKey); err != nil {
			output = err.Error()
			goto out
		}
	}
	if publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint); err != nil {
		output = err.Error()
		goto out
	}
	output = fmt.Sprintf("Private key: %v\nPublic key: %v",
		base64.RawURLEncoding.EncodeToString(privateKey),
		base64.RawURLEncoding.EncodeToString(publicKey))
out:
	fmt.Println(output)
}
