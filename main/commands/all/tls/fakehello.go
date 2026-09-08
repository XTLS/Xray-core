package tls

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/transport/internet/finalmask/rawpacket"
)

var cmdFakeHello = &base.Command{
	UsageLine: "{{.Exec}} tls fake-hello [-hex] <sni>",
	Short:     "Generate a fake TLS ClientHello payload for rawpacket",
	Long: `
Generate a fake TLS ClientHello for use in finalmask rawpacket settings.

Arguments:

	-base64
		Output base64-encoded payload (default).
	-hex
		Output hex-encoded payload instead of base64.
`,
}

func init() {
	cmdFakeHello.Run = executeFakeHello
}

var fakeHelloHex = cmdFakeHello.Flag.Bool("hex", false, "")

func executeFakeHello(cmd *base.Command, args []string) {
	if cmdFakeHello.Flag.NArg() < 1 {
		base.Fatalf("sni not specified")
	}
	sni := cmdFakeHello.Flag.Arg(0)
	payload, err := rawpacket.BuildFakeClientHello(sni)
	if err != nil {
		base.Fatalf("failed to build ClientHello: %s", err)
	}
	switch {
	case *fakeHelloHex:
		fmt.Fprintf(os.Stdout, "%x\n", payload)
	default:
		fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(payload))
	}
}
