package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/xtls/xray-core/main/commands/base"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

var cmdHash = &base.Command{
	UsageLine: "{{.Exec}} tls hash",
	Short:     "Calculate TLS certificate hash.",
	Long: `
	xray tls hash --cert <cert.pem>
	Calculate TLS certificate hash.
	`,
}

func init() {
	cmdHash.Run = executeHash // break init loop
}

var input = cmdHash.Flag.String("cert", "fullchain.pem", "The file path of the certificate")

func executeHash(cmd *base.Command, args []string) {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Println(err)
		return
	}
	certContent, err := os.ReadFile(*input)
	if err != nil {
		fmt.Println(err)
		return
	}
	var certs []*x509.Certificate
	if bytes.Contains(certContent, []byte("BEGIN")) {
		for {
			block, remain := pem.Decode(certContent)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("Unable to decode certificate:", err)
				return
			}
			certs = append(certs, cert)
			certContent = remain
		}
	} else {
		certs, err = x509.ParseCertificates(certContent)
		if err != nil {
			fmt.Println("Unable to parse certificates:", err)
			return
		}
	}
	if len(certs) == 0 {
		fmt.Println("No certificates found")
		return
	}
	tabWriter := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for i, cert := range certs {
		hash := GenerateCertHashHex(cert)
		if i == 0 {
			fmt.Fprintf(tabWriter, "Leaf SHA256:\t%s\n", hash)
		} else {
			fmt.Fprintf(tabWriter, "CA <%s> SHA256:\t%s\n", cert.Subject.CommonName, hash)
		}
	}
	tabWriter.Flush()
}
