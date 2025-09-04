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
	Short:     `Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption)`,
	Long: `
Generate key pair for ML-KEM-768 post-quantum key exchange (VLESS Encryption).

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
	seed, client, hash32 := genMLKEM768(&seed)
	fmt.Printf("Seed: %v\nClient: %v\nHash32: %v\n",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(client),
		base64.RawURLEncoding.EncodeToString(hash32[:]))
}

func genMLKEM768(inputSeed *[64]byte) (seed [64]byte, client []byte, hash32 [32]byte) {
	if inputSeed == nil {
		rand.Read(seed[:])
	} else {
		seed = *inputSeed
	}
	key, _ := mlkem.NewDecapsulationKey768(seed[:])
	client = key.EncapsulationKey().Bytes()
	hash32 = blake3.Sum256(client)
	return
}
