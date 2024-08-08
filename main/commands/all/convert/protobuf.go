package convert

import (
	"os"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"

	"google.golang.org/protobuf/proto"
)

var cmdProtobuf = &base.Command{
	CustomFlags: false,
	UsageLine:   "{{.Exec}} convert pb [json file] [json file] ...",
	Short:       "Convert multiple json configs to protobuf",
	Long: `
Convert multiple json configs to protobuf.

Examples:

    {{.Exec}} convert pb config.json c1.json c2.json c3.json > mix.pb
	`,
	Run: executeConvertConfigsToProtobuf,
}

func executeConvertConfigsToProtobuf(cmd *base.Command, args []string) {

	unnamedArgs := cmdarg.Arg{}
	for _, v := range cmd.Flag.Args() {
		unnamedArgs.Set(v)
	}

	if len(unnamedArgs) < 1 {
		base.Fatalf("empty config list")
	}

	pbConfig, err := core.LoadConfig("auto", unnamedArgs)
	if err != nil {
		base.Fatalf(err.Error())
	}

	bytesConfig, err := proto.Marshal(pbConfig)
	if err != nil {
		base.Fatalf("failed to marshal proto config: %s", err)
	}

	if _, err := os.Stdout.Write(bytesConfig); err != nil {
		base.Fatalf("failed to write proto config: %s", err)
	}
}
