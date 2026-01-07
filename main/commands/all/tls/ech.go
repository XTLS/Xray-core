package tls

import (
	"encoding/base64"
	"encoding/pem"
	"os"

	"github.com/xtls/reality/hpke"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

var cmdECH = &base.Command{
	UsageLine: `{{.Exec}} tls ech [--serverName (string)] [--pem] [-i "ECHServerKeys (base64.StdEncoding)"]`,
	Short:     `Generate TLS-ECH certificates`,
	Long: `
Generate TLS-ECH certificates.

Set serverName to your custom string: {{.Exec}} tls ech --serverName (string)
Generate into pem format: {{.Exec}} tls ech --pem
Restore ECHConfigs from ECHServerKeys: {{.Exec}} tls ech -i "ECHServerKeys (base64.StdEncoding)"
`, // Enable PQ signature schemes: {{.Exec}} tls ech --pq-signature-schemes-enabled
}

func init() {
	cmdECH.Run = executeECH
}

var input_echServerKeys = cmdECH.Flag.String("i", "", "ECHServerKeys (base64.StdEncoding)")

// var input_pqSignatureSchemesEnabled = cmdECH.Flag.Bool("pqSignatureSchemesEnabled", false, "")
var input_serverName = cmdECH.Flag.String("serverName", "cloudflare-ech.com", "")
var input_pem = cmdECH.Flag.Bool("pem", false, "True == turn on pem output")

func executeECH(cmd *base.Command, args []string) {
	var kem uint16

	// if *input_pqSignatureSchemesEnabled {
	// 	kem = 0x30 // hpke.KEM_X25519_KYBER768_DRAFT00
	// } else {
	kem = hpke.DHKEM_X25519_HKDF_SHA256
	// }

	echConfig, priv, err := tls.GenerateECHKeySet(0, *input_serverName, kem)
	common.Must(err)

	var configBuffer, keyBuffer []byte
	if *input_echServerKeys == "" {
		configBytes, _ := tls.MarshalBinary(echConfig)
		var b cryptobyte.Builder
		b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(configBytes)
		})
		configBuffer, _ = b.Bytes()
		var b2 cryptobyte.Builder
		b2.AddUint16(uint16(len(priv)))
		b2.AddBytes(priv)
		b2.AddUint16(uint16(len(configBytes)))
		b2.AddBytes(configBytes)
		keyBuffer, _ = b2.Bytes()
	} else {
		keySetsByte, err := base64.StdEncoding.DecodeString(*input_echServerKeys)
		if err != nil {
			os.Stdout.WriteString("Failed to decode ECHServerKeys: " + err.Error() + "\n")
			return
		}
		keyBuffer = keySetsByte
		KeySets, err := tls.ConvertToGoECHKeys(keySetsByte)
		if err != nil {
			os.Stdout.WriteString("Failed to decode ECHServerKeys: " + err.Error() + "\n")
			return
		}
		var b cryptobyte.Builder
		for _, keySet := range KeySets {
			b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes(keySet.Config)
			})
		}
		configBuffer, _ = b.Bytes()
	}

	if *input_pem {
		configPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBuffer}))
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keyBuffer}))
		os.Stdout.WriteString(configPEM)
		os.Stdout.WriteString(keyPEM)
	} else {
		os.Stdout.WriteString("ECH config list: \n" + base64.StdEncoding.EncodeToString(configBuffer) + "\n")
		os.Stdout.WriteString("ECH server keys: \n" + base64.StdEncoding.EncodeToString(keyBuffer) + "\n")
	}
}
