package all

import (
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdVLESSEnc = &base.Command{
	UsageLine: `{{.Exec}} vlessenc [-pq]`,
	Short:     `Generate encryption/decryption pair for VLESS encryption`,
	Long: `
Generate encryption/decryption pair with suggested default value for VLESS encryption.

Generate with MLKEM: {{.Exec}} vlessenc [-pq]"
`,
}

func init() {
	cmdVLESSEnc.Run = executeVLESSEnc // break init loop
}

var input_vlessenc_useMLKEM = cmdVLESSEnc.Flag.Bool("pq", false, "use post quantum MLKEM algorithm")

func executeVLESSEnc(cmd *base.Command, args []string) {
	var serverKey, clientKey string
	if *input_vlessenc_useMLKEM {
		seed, client, _ := genMLKEM768(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(seed[:])
		clientKey = base64.RawURLEncoding.EncodeToString(client)
	} else {
		privateKey, publicKey, _, _ := genCurve25519(nil)
		serverKey = base64.RawURLEncoding.EncodeToString(privateKey)
		clientKey = base64.RawURLEncoding.EncodeToString(publicKey)
	}
	encryption := generatePointConfig("mlkem768x25519plus", "native", "600s", serverKey)
	decryption := generatePointConfig("mlkem768x25519plus", "native", "0rtt", clientKey)
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
