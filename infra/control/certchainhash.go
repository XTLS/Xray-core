package control

import (
	"flag"
	"fmt"
	"io/ioutil"

	v2tls "github.com/v2fly/v2ray-core/v4/transport/internet/tls"
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
	certChainHashB64 := v2tls.CalculatePEMCertChainSHA256Hash(certContent)
	fmt.Println(certChainHashB64)
	return nil
}

func init() {
	// Do not release tool before v5's refactor
	// common.Must(RegisterCommand(&CertificateChainHashCommand{}))
}
