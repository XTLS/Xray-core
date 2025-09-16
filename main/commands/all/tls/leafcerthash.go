package tls

import (
	"flag"
	"fmt"
	"os"

	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var cmdLeafCertHash = &base.Command{
	UsageLine: "{{.Exec}} tls leafCertHash",
	Short:     "Calculate TLS leaf certificate hash.",
	Long: `
	xray tls leafCertHash --cert <cert.pem>
	Calculate TLS leaf certificate hash.
	`,
}

func init() {
	cmdLeafCertHash.Run = executeLeafCertHash // break init loop
}

var input = cmdLeafCertHash.Flag.String("cert", "fullchain.pem", "The file path of the leaf certificate")

func executeLeafCertHash(cmd *base.Command, args []string) {
	fs := flag.NewFlagSet("leafCertHash", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Println(err)
		return
	}
	certContent, err := os.ReadFile(*input)
	if err != nil {
		fmt.Println(err)
		return
	}
	certChainHashB64, err := tls.CalculatePEMLeafCertSHA256Hash(certContent)
	if err != nil {
		fmt.Println("failed to decode cert", err)
		return
	}
	fmt.Println(certChainHashB64)
}
