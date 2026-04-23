// keygen prints a fresh Noise NK keypair for use with the champa transport.
//
//	go run ./transport/internet/champa/example/keygen
//
// Put the privkey in the server config's champaSettings.privkey, and the
// pubkey in the client config's champaSettings.pubkey.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/xtls/xray-core/transport/internet/champa/internal/noise"
)

func main() {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	fmt.Printf("privkey: %s\n", hex.EncodeToString(privkey))
	fmt.Printf("pubkey:  %s\n", hex.EncodeToString(pubkey))
}
