package all

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/xtls/xray-core/main/commands/base"
	"lukechampine.com/blake3"
)

var cmdMLKEM768 = &base.Command{
	UsageLine: `{{.Exec}} mlkem768 [-i "seed (base64.RawURLEncoding)"]`,
	Short:     `Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS)`,
	Long: `
Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS).

Random: {{.Exec}} mlkem768

From seed: {{.Exec}} mlkem768 -i "seed (base64.RawURLEncoding)"
`,
}

func init() {
	cmdMLKEM768.Run = executeMLKEM768 // break init loop
}

var input_mlkem768 = cmdMLKEM768.Flag.String("i", "", "")

func executeMLKEM768(cmd *base.Command, args []string) {
	var seed [64]byte
	if len(*input_mlkem768) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(*input_mlkem768)
		if len(s) != 64 {
			fmt.Println("Invalid length of ML-KEM-768 seed.")
			return
		}
		seed = [64]byte(s)
	} else {
		rand.Read(seed[:])
	}
	key, _ := mlkem.NewDecapsulationKey768(seed[:])
	client := key.EncapsulationKey().Bytes()
	hash32 := blake3.Sum256(client)
	fmt.Printf("Seed: %v\nClient: %v\nHash32: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(client),
		base64.RawURLEncoding.EncodeToString(hash32[:]))
}
