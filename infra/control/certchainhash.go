package control

import (
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/v2fly/v2ray-core/v4/common"
	v2tls "github.com/v2fly/v2ray-core/v4/transport/internet/tls"
	"io/ioutil"
)

type CertificateChainHashCommand struct {
}

func (c CertificateChainHashCommand) Name() string {
	return "certChainHash"
}

func (c CertificateChainHashCommand) Description() Description {
	return Description{
		Short: "Calculate TLS certificates hash.",
		Usage: []string{
			"v2ctl certChainHash --cert <cert.pem>",
			"Calculate TLS certificate chain hash.",
		},
	}
}

func (c CertificateChainHashCommand) Execute(args []string) error {
	fs := flag.NewFlagSet(c.Name(), flag.ContinueOnError)
	cert := fs.String("cert", "fullchain.pem", "The file path of the certificates chain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	certContent, err := ioutil.ReadFile(*cert)
	if err != nil {
		return err
	}
	var certChain [][]byte
	for {
		block, remain := pem.Decode(certContent)
		if block == nil {
			break
		}
		certChain = append(certChain, block.Bytes)
		certContent = remain
	}
	certChainHash := v2tls.GenerateCertChainHash(certChain)
	certChainHashB64 := base64.StdEncoding.EncodeToString(certChainHash)
	fmt.Println(certChainHashB64)
	return nil
}

func init() {
	common.Must(RegisterCommand(&CertificateChainHashCommand{}))
}
