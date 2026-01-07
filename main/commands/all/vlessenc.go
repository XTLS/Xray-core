package all

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdVLESSEnc = &base.Command{
	UsageLine: `{{.Exec}} vlessenc`,
	Short:     `Generate decryption/encryption json pair (VLESS Encryption)`,
	Long: `
Generate decryption/encryption json pair (VLESS Encryption).
`,
}

func init() {
	cmdVLESSEnc.Run = executeVLESSEnc // break init loop
}

func executeVLESSEnc(cmd *base.Command, args []string) {
	privateKey, password, _, _ := genCurve25519(nil)
	serverKey := base64.RawURLEncoding.EncodeToString(privateKey)
	clientKey := base64.RawURLEncoding.EncodeToString(password)
	decryption := generateDotConfig("mlkem768x25519plus", "native", "600s", serverKey)
	encryption := generateDotConfig("mlkem768x25519plus", "native", "0rtt", clientKey)
	seed, client, _ := genMLKEM768(nil)
	serverKeyPQ := base64.RawURLEncoding.EncodeToString(seed[:])
	clientKeyPQ := base64.RawURLEncoding.EncodeToString(client)
	decryptionPQ := generateDotConfig("mlkem768x25519plus", "native", "600s", serverKeyPQ)
	encryptionPQ := generateDotConfig("mlkem768x25519plus", "native", "0rtt", clientKeyPQ)
	fmt.Printf("Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n\n")
	fmt.Printf("Authentication: X25519, not Post-Quantum\n\"decryption\": \"%v\"\n\"encryption\": \"%v\"\n\n", decryption, encryption)
	fmt.Printf("Authentication: ML-KEM-768, Post-Quantum\n\"decryption\": \"%v\"\n\"encryption\": \"%v\"\n", decryptionPQ, encryptionPQ)
}

func generateDotConfig(fields ...string) string {
	return strings.Join(fields, ".")
}
