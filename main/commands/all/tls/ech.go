package tls

import (
	"encoding/pem"
	"os"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdECH = &base.Command{
	UsageLine: `{{.Exec}} tls ech [--serverName (string)] [--pem]`,
	Short:     `Generate TLS-ECH certificates`,
	Long: `
Generate TLS-ECH certificates.

Set serverName to your custom string: {{.Exec}} tls ech --serverName (string)
Generate into pem format: {{.Exec}} tls ech --pem
`, // Enable PQ signature schemes: {{.Exec}} tls ech --pq-signature-schemes-enabled
}

func init() {
	cmdECH.Run = executeECH
}

var input_pqSignatureSchemesEnabled = cmdECH.Flag.Bool("pqSignatureSchemesEnabled", false, "")
var input_serverName = cmdECH.Flag.String("serverName", "cloudflare-ech.com", "")
var input_pem = cmdECH.Flag.Bool("pem", false, "True == turn on pem output")

func executeECH(cmd *base.Command, args []string) {
	var kem hpke.KEM

	if *input_pqSignatureSchemesEnabled {
		kem = hpke.KEM_X25519_KYBER768_DRAFT00
	} else {
		kem = hpke.KEM_X25519_HKDF_SHA256
	}

	echKeySet, err := goech.GenerateECHKeySet(0, *input_serverName, kem, nil)
	common.Must(err)

	// Make single key set to a list with only one element
	ECHConfigList := make(goech.ECHConfigList, 1)
	ECHConfigList[0] = echKeySet.ECHConfig
	ECHKeySetList := make(goech.ECHKeySetList, 1)
	ECHKeySetList[0] = echKeySet
	configBuffer, _ := ECHConfigList.MarshalBinary()
	keyBuffer, _ := ECHKeySetList.MarshalBinary()
	configStr, _ := ECHConfigList.ToBase64()
	keySetStr, _ := ECHKeySetList.ToBase64()

	configPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBuffer}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keyBuffer}))
	if *input_pem {
		os.Stdout.WriteString(configPEM)
		os.Stdout.WriteString(keyPEM)
	} else {
		os.Stdout.WriteString("ECH config list: \n" + configStr + "\n")
		os.Stdout.WriteString("ECH Key sets: \n" + keySetStr + "\n")
	}
}
