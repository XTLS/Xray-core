package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"

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

	domain := cmdPing.Flag.Arg(0)
	fmt.Println("Tls ping: ", domain)

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
	fmt.Println("Using IP: ", ip.String())

	fmt.Println("-------------------")
	fmt.Println("Pinging without SNI")
	{
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: 443})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := gotls.Client(tcpConn, &gotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			MaxVersion:         gotls.VersionTLS12,
			MinVersion:         gotls.VersionTLS12,
			// Do not release tool before v5's refactor
			// VerifyPeerCertificate: showCert(),
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			printCertificates(tlsConn.ConnectionState().PeerCertificates)
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("Pinging with SNI")
	{
		tcpConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: ip, Port: 443})
		if err != nil {
			base.Fatalf("Failed to dial tcp: %s", err)
		}
		tlsConn := gotls.Client(tcpConn, &gotls.Config{
			ServerName: domain,
			NextProtos: []string{"http/1.1"},
			MaxVersion: gotls.VersionTLS12,
			MinVersion: gotls.VersionTLS12,
			// Do not release tool before v5's refactor
			// VerifyPeerCertificate: showCert(),
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("handshake failure: ", err)
		} else {
			fmt.Println("handshake succeeded")
			printCertificates(tlsConn.ConnectionState().PeerCertificates)
		}
		tlsConn.Close()
	}

	fmt.Println("Tls ping finished")
}

func printCertificates(certs []*x509.Certificate) {
	for _, cert := range certs {
		if len(cert.DNSNames) == 0 {
			continue
		}
		fmt.Println("Allowed domains: ", cert.DNSNames)
	}
}

func showCert() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		hash := GenerateCertChainHash(rawCerts)
		fmt.Println("Certificate Chain Hash: ", base64.StdEncoding.EncodeToString(hash))
		return nil
	}
}
