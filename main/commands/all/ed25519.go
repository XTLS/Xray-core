package all

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEd25519 = &base.Command{
	UsageLine: `{{.Exec}} ed25519 [-i "private key seed (Base64URL)"]`,
	Short:     "Generate an Ed25519 key pair",
	Long: `
Generate an Ed25519 key pair, or restore it from a 32-byte private key seed
with -i. PrivateKey (seed) and PublicKey use unpadded Base64URL.
`,
}

var inputEd25519 = cmdEd25519.Flag.String("i", "", "Ed25519 private key seed in unpadded Base64URL.")

func init() {
	cmdEd25519.Run = executeEd25519
}

func executeEd25519(cmd *base.Command, args []string) {
	if len(args) != 0 {
		cmd.Usage()
	}

	var privateKey ed25519.PrivateKey
	if *inputEd25519 == "" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			base.Fatalf("failed to generate Ed25519 key: %s", err)
		}
		privateKey = key
	} else {
		encoding := base64.RawURLEncoding.Strict()
		seed, err := encoding.DecodeString(*inputEd25519)
		if err != nil || len(seed) != ed25519.SeedSize || encoding.EncodeToString(seed) != *inputEd25519 {
			base.Fatalf("invalid Ed25519 private key seed: expected 32 bytes in unpadded Base64URL")
		}
		privateKey = ed25519.NewKeyFromSeed(seed)
	}

	if _, err := fmt.Printf("PrivateKey: %s\nPublicKey: %s\n",
		base64.RawURLEncoding.EncodeToString(privateKey.Seed()),
		base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))); err != nil {
		base.Fatalf("failed to write Ed25519 keys: %s", err)
	}
}
