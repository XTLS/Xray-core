package all

import (
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdVLESSEncryption = &base.Command{
	UsageLine: `{{.Exec}} vlessencryption [-key x25519/mlkem]`,
	Short:     `Generate encryption/decryption pair for VLESS encryption`,
	Long: `
Generate encryption/decryption pair with suggested default value for VLESS encryption.

Random: {{.Exec}} vlessencryption

From seed: {{.Exec}} vlessencryption [-key x25519/mlkem] [-mode native/xorpub/random]"
`,
}

func init() {
	cmdVLESSEncryption.Run = executeVLESSEncryption // break init loop
}

var input_vlessencryption_key = cmdVLESSEncryption.Flag.String("key", "x25519", "")
var input_vlessencryption_mode = cmdVLESSEncryption.Flag.String("mode", "random", "")

func executeVLESSEncryption(cmd *base.Command, args []string) {
	switch *input_vlessencryption_mode {
	case "native", "random", "xorpub":
	default:
		fmt.Println("invalid mode: ", *input_vlessencryption_mode)
		return
	}
	var serverKey, clientKey string
	switch *input_vlessencryption_key {
	case "x25519":
		privateKey, publicKey, _, _ := genCurve25519(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(privateKey)
		clientKey = base64.RawURLEncoding.EncodeToString(publicKey)
	case "mlkem":
		seed, client, _ := genMLKEM768(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(seed[:])
		clientKey = base64.RawURLEncoding.EncodeToString(client)
	default:
		fmt.Println("invalid key type: ", *input_vlessencryption_key)
		return
	}
	encryption := generatePointConfig("mlkem768x25519plus", *input_vlessencryption_mode, "600s", serverKey)
	decryption := generatePointConfig("mlkem768x25519plus", *input_vlessencryption_mode, "0rtt", clientKey)
	fmt.Printf("------encryption------\n%v\n------decryption------\n%v\n", decryption, encryption)
}

func generatePointConfig(fields ...string) string {
	result := ""
	for i, field := range fields {
		result += field
		if i != len(fields)-1 {
			result += "."
		}
	}
	return result
}
