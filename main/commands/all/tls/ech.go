package tls

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdECH = &base.Command{
	UsageLine: `{{.Exec}} tls ech [--serverName (string)] [--json]`,
	Short:     `Generate TLS-ECH certificates`,
	Long: `
Generate TLS-ECH certificates.

Set serverName to your custom string: {{.Exec}} tls ech --serverName (string)
Generate into json format: {{.Exec}} tls ech --json
`, // Enable PQ signature schemes: {{.Exec}} tls ech --pq-signature-schemes-enabled
}

func init() {
	cmdECH.Run = executeECH
}

var input_pqSignatureSchemesEnabled = cmdECH.Flag.Bool("pqSignatureSchemesEnabled", false, "")
var input_serverName = cmdECH.Flag.String("serverName", "cloudflare-ech.com", "")
var input_json = cmdECH.Flag.Bool("json", false, "True == turn on json output")

func executeECH(cmd *base.Command, args []string) {
	var kem hpke.KEM

	if *input_pqSignatureSchemesEnabled {
		kem = hpke.KEM_X25519_KYBER768_DRAFT00
	} else {
		kem = hpke.KEM_X25519_HKDF_SHA256
	}

	echKeySet, err := goech.GenerateECHKeySet(0, *input_serverName, kem)
	common.Must(err)

	configBuffer, _ := echKeySet.ECHConfig.MarshalBinary()
	keyBuffer, _ := echKeySet.MarshalBinary()

	configPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBuffer}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keyBuffer}))
	if *input_json {
		jECHConfigs := map[string]interface{}{
			"configs": strings.Split(strings.TrimSpace(string(configPEM)), "\n"),
		}
		jECHKey := map[string]interface{}{
			"key": strings.Split(strings.TrimSpace(string(keyPEM)), "\n"),
		}

		for _, i := range []map[string]interface{}{jECHConfigs, jECHKey} {
			content, err := json.MarshalIndent(i, "", "  ")
			common.Must(err)
			os.Stdout.Write(content)
			os.Stdout.WriteString("\n")
		}
	} else {
		os.Stdout.WriteString(configPEM)
		os.Stdout.WriteString(keyPEM)
	}
}
