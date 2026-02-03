package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"

	utls "github.com/refraction-networking/utls"

	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/main/commands/base"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

// cmdPing is the tls ping command
var cmdPing = &base.Command{
	UsageLine: "{{.Exec}} tls ping [-ip <ip>] <domain>",
	Short:     "Ping the domain with TLS handshake",
	Long: `
Ping the domain with TLS handshake.

Arguments:

	-ip
		The IP address of the domain.
`,
}

func init() {
	cmdPing.Run = executePing // break init loop
}

var pingIPStr = cmdPing.Flag.String("ip", "", "")

func executePing(cmd *base.Command, args []string) {
	if cmdPing.Flag.NArg() < 1 {
		base.Fatalf("domain not specified")
	}

	domainWithPort := cmdPing.Flag.Arg(0)
	fmt.Println("TLS ping: ", domainWithPort)
	TargetPort := 443
	domain, port, err := net.SplitHostPort(domainWithPort)
	if err != nil {
		domain = domainWithPort
	} else {
		TargetPort, _ = strconv.Atoi(port)
	}
	tabWriter := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	var ip net.IP
	if len(*pingIPStr) > 0 {
		v := net.ParseIP(*pingIPStr)
		if v == nil {
			base.Fatalf("invalid IP: %s", *pingIPStr)
		}
		ip = v
	} else {
		v, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			base.Fatalf("Failed to resolve IP: %s", err)
		}
		ip = v.IP
	}
	fmt.Println("Using IP: ", ip.String()+":"+strconv.Itoa(TargetPort))

	fmt.Println("-------------------")
	fmt.Println("Pinging without SNI")
	{
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: TargetPort})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := GeneraticUClient(tcpConn, &gotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MaxVersion:         gotls.VersionTLS13,
			MinVersion:         gotls.VersionTLS12,
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			printTLSConnDetail(tabWriter, tlsConn)
			printCertificates(tabWriter, tlsConn.ConnectionState().PeerCertificates)
			tabWriter.Flush()
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("Pinging with SNI")
	{
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: TargetPort})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := GeneraticUClient(tcpConn, &gotls.Config{
			ServerName: domain,
			NextProtos: []string{"h2", "http/1.1"},
			MaxVersion: gotls.VersionTLS13,
			MinVersion: gotls.VersionTLS12,
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			printTLSConnDetail(tabWriter, tlsConn)
			printCertificates(tabWriter, tlsConn.ConnectionState().PeerCertificates)
			tabWriter.Flush()
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("TLS ping finished")
}

func printCertificates(tabWriter *tabwriter.Writer, certs []*x509.Certificate) {
	var leaf *x509.Certificate
	var CAs []*x509.Certificate
	var length int
	for _, cert := range certs {
		length += len(cert.Raw)
		if len(cert.DNSNames) != 0 {
			leaf = cert
		} else {
			CAs = append(CAs, cert)
		}
	}
	fmt.Fprintf(tabWriter, "Certificate chain's total length: \t %d (certs count: %s)\n", length, strconv.Itoa(len(certs)))
	if leaf != nil {
		fmt.Fprintf(tabWriter, "Cert's signature algorithm: \t %s\n", leaf.SignatureAlgorithm.String())
		fmt.Fprintf(tabWriter, "Cert's publicKey algorithm: \t %s\n", leaf.PublicKeyAlgorithm.String())
		fmt.Fprintf(tabWriter, "Cert's leaf SHA256: \t %s\n", hex.EncodeToString(GenerateCertHash(leaf)))
		for _, ca := range CAs {
			fmt.Fprintf(tabWriter, "Cert's CA: %s SHA256: \t %s\n", ca.Subject.CommonName, hex.EncodeToString(GenerateCertHash(ca)))
		}
		fmt.Fprintf(tabWriter, "Cert's allowed domains: \t %v\n", leaf.DNSNames)
	}
}

func printTLSConnDetail(tabWriter *tabwriter.Writer, tlsConn *utls.UConn) {
	connectionState := tlsConn.ConnectionState()
	var tlsVersion string
	switch connectionState.Version {
	case gotls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	case gotls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	}
	fmt.Fprintf(tabWriter, "TLS Version: \t %s\n", tlsVersion)
	curveID := utils.AccessField[utls.CurveID](tlsConn.Conn, "curveID")
	if curveID != nil {
		PostQuantum := (*curveID == utls.X25519MLKEM768)
		fmt.Fprintf(tabWriter, "TLS Post-Quantum key exchange: \t %t (%s)\n", PostQuantum, curveID.String())
	} else {
		fmt.Fprintf(tabWriter, "TLS Post-Quantum key exchange:  false (RSA Exchange)\n")
	}
}
