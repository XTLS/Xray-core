package tls

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

var cmdECH = &base.Command{
	CustomFlags: true,
	UsageLine:   `{{.Exec}} tls ech [--serverName (string)] [--pem] [-i "ECHServerKeys (base64.StdEncoding)"]`,
	Short:       `Generate TLS-ECH certificates`,
	Long: `
Generate TLS-ECH certificates.

Arguments:

	-serverName
		Set serverName to your custom string.
	
	-pem
		Generate into pem format.

	-i
		Restore ECHConfigs from ECHServerKeys.
`,
	// --pq-signature-schemes-enabled
	//     Enable PQ signature schemes.
	Run: executeECH,
}

func executeECH(cmd *base.Command, args []string) {
	var input_echServerKeys = cmd.Flag.String("i", "", "ECHServerKeys (base64.StdEncoding)")
	// var input_pqSignatureSchemesEnabled = cmdECH.Flag.Bool("pqSignatureSchemesEnabled", false, "")
	var input_serverName = cmd.Flag.String("serverName", "cloudflare-ech.com", "")
	var input_pem = cmd.Flag.Bool("pem", false, "True == turn on pem output")
	cmd.Flag.Parse(args)
	var kem uint16

	var configBuffer, keyBuffer []byte
	if *input_echServerKeys == "" {
		// if *input_pqSignatureSchemesEnabled {
		// 	kem = 0x30 // hpke.KEM_X25519_KYBER768_DRAFT00
		// } else {
		kem = hpke.DHKEM(ecdh.X25519()).ID()
		// }
		echConfig, priv, err := generateECHKeySet(0, *input_serverName, kem)
		common.Must(err)
		configBytes, _ := marshalBinary(echConfig)
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

type EchConfig struct {
	Version              uint16
	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []EchCipher
	MaxNameLength        uint8
	PublicName           []byte
	Extensions           []Extension
}

type EchCipher struct {
	KDFID  uint16
	AEADID uint16
}

type Extension struct {
	Type uint16
	Data []byte
}

// reference github.com/OmarTariq612/goech
func marshalBinary(ech EchConfig) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(ech.Version)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddUint8(ech.ConfigID)
		child.AddUint16(ech.KemID)
		child.AddUint16(uint16(len(ech.PublicKey)))
		child.AddBytes(ech.PublicKey)
		child.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			for _, cipherSuite := range ech.SymmetricCipherSuite {
				child.AddUint16(cipherSuite.KDFID)
				child.AddUint16(cipherSuite.AEADID)
			}
		})
		child.AddUint8(ech.MaxNameLength)
		child.AddUint8(uint8(len(ech.PublicName)))
		child.AddBytes(ech.PublicName)
		child.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			for _, extention := range ech.Extensions {
				child.AddUint16(extention.Type)
				child.AddBytes(extention.Data)
			}
		})
	})
	return b.Bytes()
}

const ExtensionEncryptedClientHello = 0xfe0d

func generateECHKeySet(configID uint8, domain string, kem uint16) (EchConfig, []byte, error) {
	config := EchConfig{
		Version:    ExtensionEncryptedClientHello,
		ConfigID:   configID,
		PublicName: []byte(domain),
		KemID:      kem,
		SymmetricCipherSuite: []EchCipher{
			{KDFID: hpke.HKDFSHA256().ID(), AEADID: hpke.AES128GCM().ID()},
			{KDFID: hpke.HKDFSHA256().ID(), AEADID: hpke.AES256GCM().ID()},
			{KDFID: hpke.HKDFSHA256().ID(), AEADID: hpke.ChaCha20Poly1305().ID()},
			{KDFID: hpke.HKDFSHA384().ID(), AEADID: hpke.AES128GCM().ID()},
			{KDFID: hpke.HKDFSHA384().ID(), AEADID: hpke.AES256GCM().ID()},
			{KDFID: hpke.HKDFSHA384().ID(), AEADID: hpke.ChaCha20Poly1305().ID()},
			{KDFID: hpke.HKDFSHA512().ID(), AEADID: hpke.AES128GCM().ID()},
			{KDFID: hpke.HKDFSHA512().ID(), AEADID: hpke.AES256GCM().ID()},
			{KDFID: hpke.HKDFSHA512().ID(), AEADID: hpke.ChaCha20Poly1305().ID()},
		},
		MaxNameLength: 0,
		Extensions:    nil,
	}
	// if kem == hpke.DHKEM_X25519_HKDF_SHA256 {
	curve := ecdh.X25519()
	priv := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, priv)
	if err != nil {
		return config, nil, err
	}
	privKey, _ := curve.NewPrivateKey(priv)
	config.PublicKey = privKey.PublicKey().Bytes()
	return config, priv, nil
}
