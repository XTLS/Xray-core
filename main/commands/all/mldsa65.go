package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdMLDSA65 = &base.Command{
	UsageLine: `{{.Exec}} mldsa65 [-i "seed (base64.RawURLEncoding)"]`,
	Short:     `Generate key pair for ML-DSA-65 post-quantum signature`,
	Long: `
Generate key pair for ML-DSA-65 post-quantum signature.

Random: {{.Exec}} mldsa65

From seed: {{.Exec}} mldsa65 -i "seed (base64.RawURLEncoding)"
`,
}

func init() {
	cmdMLDSA65.Run = executeMLDSA65 // break init loop
}

var input_seed = cmdMLDSA65.Flag.String("i", "", "")

func executeMLDSA65(cmd *base.Command, args []string) {
	var seed [32]byte
	if len(*input_seed) > 0 {
		s, _ := base64.RawURLEncoding.DecodeString(*input_seed)
		seed = [32]byte(s)
	} else {
		rand.Read(seed[:])
	}
	pub, _ := mldsa65.NewKeyFromSeed(&seed)
	fmt.Printf("Seed: %v\nVerify: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()))
}
