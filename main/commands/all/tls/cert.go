package tls

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/main/commands/base"
)

// cmdCert is the tls cert command
var cmdCert = &base.Command{
	UsageLine: "{{.Exec}} tls cert [--ca] [--domain=example.com] [--expire=240h]",
	Short:     "Generate TLS certificates",
	Long: `
Generate TLS certificates.

Arguments:

	-domain=domain_name 
		The domain name for the certificate.

	-name=common_name 
		The common name for the certificate.

	-org=organization 
		The organization name for the certificate.

	-ca 
		Whether this certificate is a CA

	-json 
		The output of certificate to JSON

	-file 
		The certificate path to save.

	-expire 
		Expire time of the certificate. Default value 3 months.
`,
}

func init() {
	cmdCert.Run = executeCert // break init loop
}

var (
	certDomainNames stringList
	_               = func() bool {
		cmdCert.Flag.Var(&certDomainNames, "domain", "Domain name for the certificate")
		return true
	}()

	certCommonName   = cmdCert.Flag.String("name", "Xray Inc", "The common name of this certificate")
	certOrganization = cmdCert.Flag.String("org", "Xray Inc", "Organization of the certificate")
	certIsCA         = cmdCert.Flag.Bool("ca", false, "Whether this certificate is a CA")
	certJSONOutput   = cmdCert.Flag.Bool("json", true, "Print certificate in JSON format")
	certFileOutput   = cmdCert.Flag.String("file", "", "Save certificate in file.")
	certExpire       = cmdCert.Flag.Duration("expire", time.Hour*24*90 /* 90 days */, "Time until the certificate expires. Default value 3 months.")
)

func executeCert(cmd *base.Command, args []string) {
	var opts []cert.Option
	if *certIsCA {
		opts = append(opts, cert.Authority(*certIsCA))
		opts = append(opts, cert.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature))
	}

	opts = append(opts, cert.NotAfter(time.Now().Add(*certExpire)))
	opts = append(opts, cert.CommonName(*certCommonName))
	if len(certDomainNames) > 0 {
		opts = append(opts, cert.DNSNames(certDomainNames...))
	}
	opts = append(opts, cert.Organization(*certOrganization))

	cert, err := cert.Generate(nil, opts...)
	if err != nil {
		base.Fatalf("failed to generate TLS certificate: %s", err)
	}

	if *certJSONOutput {
		printJSON(cert)
	}

	if len(*certFileOutput) > 0 {
		if err := printFile(cert, *certFileOutput); err != nil {
			base.Fatalf("failed to save file: %s", err)
		}
	}
}

func printJSON(certificate *cert.Certificate) {
	certPEM, keyPEM := certificate.ToPEM()
	jCert := &jsonCert{
		Certificate: strings.Split(strings.TrimSpace(string(certPEM)), "\n"),
		Key:         strings.Split(strings.TrimSpace(string(keyPEM)), "\n"),
	}
	content, err := json.MarshalIndent(jCert, "", "  ")
	common.Must(err)
	os.Stdout.Write(content)
	os.Stdout.WriteString("\n")
}

func writeFile(content []byte, name string) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return common.Error2(f.Write(content))
}

func printFile(certificate *cert.Certificate, name string) error {
	certPEM, keyPEM := certificate.ToPEM()
	return task.Run(context.Background(), func() error {
		return writeFile(certPEM, name+".crt")
	}, func() error {
		return writeFile(keyPEM, name+".key")
	})
}

type stringList []string

func (l *stringList) String() string {
	return "String list"
}

func (l *stringList) Set(v string) error {
	if v == "" {
		base.Fatalf("empty value")
	}
	*l = append(*l, v)
	return nil
}

type jsonCert struct {
	Certificate []string `json:"certificate"`
	Key         []string `json:"key"`
}
