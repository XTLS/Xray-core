package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"

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
		tlsConn := gotls.Client(tcpConn, &gotls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MaxVersion:         gotls.VersionTLS13,
			MinVersion:         gotls.VersionTLS12,
			// Do not release tool before v5's refactor
			// VerifyPeerCertificate: showCert(),
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			printTLSConnDetail(tlsConn)
			printCertificates(tlsConn.ConnectionState().PeerCertificates)
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
		tlsConn := gotls.Client(tcpConn, &gotls.Config{
			ServerName: domain,
			NextProtos: []string{"h2", "http/1.1"},
			MaxVersion: gotls.VersionTLS13,
			MinVersion: gotls.VersionTLS12,
			// Do not release tool before v5's refactor
			// VerifyPeerCertificate: showCert(),
		})
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("Handshake failure: ", err)
		} else {
			fmt.Println("Handshake succeeded")
			printTLSConnDetail(tlsConn)
			printCertificates(tlsConn.ConnectionState().PeerCertificates)
		}
		tlsConn.Close()
	}

	fmt.Println("-------------------")
	fmt.Println("TLS ping finished")
}

func printCertificates(certs []*x509.Certificate) {
	var leaf *x509.Certificate
	var length int
	for _, cert := range certs {
		length += len(cert.Raw)
		if len(cert.DNSNames) != 0 {
			leaf = cert
		}
	}
	fmt.Println("Certificate chain's total length: ", length, "(certs count: "+strconv.Itoa(len(certs))+")")
	if leaf != nil {
		fmt.Println("Cert's signature algorithm: ", leaf.SignatureAlgorithm.String())
		fmt.Println("Cert's publicKey algorithm: ", leaf.PublicKeyAlgorithm.String())
		fmt.Println("Cert's allowed domains: ", leaf.DNSNames)
	}
}

func printTLSConnDetail(tlsConn *gotls.Conn) {
	connectionState := tlsConn.ConnectionState()
	var tlsVersion string
	if connectionState.Version == gotls.VersionTLS13 {
		tlsVersion = "TLS 1.3"
	} else if connectionState.Version == gotls.VersionTLS12 {
		tlsVersion = "TLS 1.2"
	}
	fmt.Println("TLS Version: ", tlsVersion)
	curveID := connectionState.CurveID
	if curveID != 0 {
		PostQuantum := (curveID == gotls.X25519MLKEM768)
		fmt.Println("TLS Post-Quantum key exchange: ", PostQuantum, "("+curveID.String()+")")
	} else {
		fmt.Println("TLS Post-Quantum key exchange:  false (RSA Exchange)")
	}
}

func showCert() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		hash := GenerateCertChainHash(rawCerts)
		fmt.Println("Certificate Chain Hash: ", base64.StdEncoding.EncodeToString(hash))
		return nil
	}
}
