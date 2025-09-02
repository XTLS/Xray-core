package all

import (
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdVLESSEnc = &base.Command{
	UsageLine: `{{.Exec}} vlessenc [-key x25519/mlkem]`,
	Short:     `Generate encryption/decryption pair for VLESS encryption`,
	Long: `
Generate encryption/decryption pair with suggested default value for VLESS encryption.

Custom key type and mode: {{.Exec}} vlessenc [-key x25519/mlkem] [-mode native/xorpub/random]"
`,
}

func init() {
	cmdVLESSEnc.Run = executeVLESSEnc // break init loop
}

var input_vlessenc_key = cmdVLESSEnc.Flag.String("key", "x25519", "")
var input_vlessenc_mode = cmdVLESSEnc.Flag.String("mode", "random", "")

func executeVLESSEnc(cmd *base.Command, args []string) {
	switch *input_vlessenc_mode {
	case "native", "random", "xorpub":
	default:
		fmt.Println("invalid mode: ", *input_vlessenc_mode)
		return
	}
	var serverKey, clientKey string
	switch *input_vlessenc_key {
	case "x25519":
		privateKey, publicKey, _, _ := genCurve25519(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(privateKey)
		clientKey = base64.RawURLEncoding.EncodeToString(publicKey)
	case "mlkem":
		seed, client, _ := genMLKEM768(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(seed[:])
		clientKey = base64.RawURLEncoding.EncodeToString(client)
	default:
		fmt.Println("invalid key type: ", *input_vlessenc_key)
		return
	}
	encryption := generatePointConfig("mlkem768x25519plus", *input_vlessenc_mode, "600s", serverKey)
	decryption := generatePointConfig("mlkem768x25519plus", *input_vlessenc_mode, "0rtt", clientKey)
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
