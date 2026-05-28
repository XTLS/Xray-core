package all

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdMinecraftRSA = &base.Command{
	UsageLine: `{{.Exec}} minecraft`,
	Short:     `Generate RSA private key used in Minecraft finalmask`,
	Long: `
Generate RSA private key used in Minecraft finalmask.

Output private key in PEM format and the SHA256 of the public key in PKIX format.
`,
}

func init() {
	cmdMinecraftRSA.Run = executeMinecraftRSA // break init loop
}

func executeMinecraftRSA(cmd *base.Command, args []string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	pkcs8pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs8,
	})

	fmt.Println("Private Key:")
	fmt.Println(strings.ReplaceAll(string(pkcs8pem), "\n", "\\n"))

	rsaPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	h := sha256.New()
	h.Write(rsaPublicKey)
	hash := h.Sum([]byte{})

	fmt.Println("Public Key SHA256:")
	fmt.Println(hex.EncodeToString(hash))
}
