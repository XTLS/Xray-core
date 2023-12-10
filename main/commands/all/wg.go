package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
	"golang.org/x/crypto/curve25519"
)

var cmdWG = &base.Command{
	UsageLine: `{{.Exec}} wg [-i "private key (base64.StdEncoding)"]`,
	Short:     `Generate key pair for wireguard key exchange`,
	Long: `
Generate key pair for wireguard key exchange.

Random: {{.Exec}} wg

From private key: {{.Exec}} wg -i "private key (base64.StdEncoding)"
`,
}

func init() {
	cmdWG.Run = executeWG // break init loop
}

var input_curve25519 = cmdWG.Flag.String("i", "", "")

func executeWG(cmd *base.Command, args []string) {
	var output string
	var err error
	var privateKey, publicKey []byte
	var encoding = base64.StdEncoding

	if len(*input_curve25519) > 0 {
		privateKey, err = base64.StdEncoding.DecodeString(*input_curve25519)
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
	privateKey[31] &= 127 | 64

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
