package all

import (
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdVLESSEnc = &base.Command{
	UsageLine: `{{.Exec}} vlessenc [-pq]`,
	Short:     `Generate encryption/decryption pair for VLESS encryption (VLESS)`,
	Long: `
Generate encryption/decryption pair with suggested default value for VLESS encryption (VLESS).

Generate with MLKEM: {{.Exec}} vlessenc"
`,
}

func init() {
	cmdVLESSEnc.Run = executeVLESSEnc // break init loop
}

func executeVLESSEnc(cmd *base.Command, args []string) {
	fmt.Printf("Choose one authentication to use, do not mix them. Key exchange is Post-Quantum safe anyway.\n\n")
	privateKey, password, _, _ := genCurve25519(nil)
	serverKey := base64.RawURLEncoding.EncodeToString(privateKey)
	clientKey := base64.RawURLEncoding.EncodeToString(password)
	decryption := generatePointConfig("mlkem768x25519plus", "native", "600s", serverKey)
	encryption := generatePointConfig("mlkem768x25519plus", "native", "0rtt", clientKey)
	fmt.Printf("------ decryption (Authentication: X25519, not Post-Quantum) ------\n%v\n------ encryption (Authentication: X25519, not Post-Quantum) ------\n%v\n", decryption, encryption)
	fmt.Println("")
	seed, client, _ := genMLKEM768(nil)
	serverKeyPQ := base64.RawURLEncoding.EncodeToString(seed[:])
	clientKeyPQ := base64.RawURLEncoding.EncodeToString(client)
	decryptionPQ := generatePointConfig("mlkem768x25519plus", "native", "600s", serverKeyPQ)
	encryptionPQ := generatePointConfig("mlkem768x25519plus", "native", "0rtt", clientKeyPQ)
	fmt.Printf("------ decryption (Authentication: ML-KEM-768, Post-Quantum) ------\n%v\n------ encryption (Authentication: ML-KEM-768, Post-Quantum) ------\n%v\n", decryptionPQ, encryptionPQ)
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
