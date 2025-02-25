package convert

import (
	"fmt"
	"os"

	"github.com/xtls/xray-core/common/cmdarg"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"

	"google.golang.org/protobuf/proto"
)

var cmdProtobuf = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} convert pb [-debug] [-type] [json file] [json file] ...",
	Short:       "Convert multiple json configs to protobuf",
	Long: `
Convert multiple json configs to protobuf.

Arguments:

	-d, -debug
		Show mix.pb as json.
		FOR DEBUGGING ONLY!
		DO NOT PASS THIS OUTPUT TO XRAY-CORE!

	-t, -type
		Inject type information into debug output.

Examples:

    {{.Exec}} convert pb config.json c1.json c2.json c3.json > mix.pb
	`,
	Run: executeConvertConfigsToProtobuf,
}

func executeConvertConfigsToProtobuf(cmd *base.Command, args []string) {

	var optDump bool
	var optType bool

	cmd.Flag.BoolVar(&optDump, "d", false, "")
	cmd.Flag.BoolVar(&optDump, "debug", false, "")
	cmd.Flag.BoolVar(&optType, "t", false, "")
	cmd.Flag.BoolVar(&optType, "type", false, "")
	cmd.Flag.Parse(args)

	unnamedArgs := cmdarg.Arg{}
	for _, v := range cmd.Flag.Args() {
		unnamedArgs.Set(v)
	}

	if len(unnamedArgs) < 1 {
		base.Fatalf("invalid config list length: %d", len(unnamedArgs))
	}

	pbConfig, err := core.LoadConfig("auto", unnamedArgs)
	if err != nil {
		base.Fatalf("failed to load config: %s", err)
	}

	if optDump {
		if j, ok := creflect.MarshalToJson(pbConfig, optType); ok {
			fmt.Println(j)
			return
		} else {
			base.Fatalf("failed to marshal proto config to json.")
		}
	}

	bytesConfig, err := proto.Marshal(pbConfig)
	if err != nil {
		base.Fatalf("failed to marshal proto config: %s", err)
	}

	if _, err := os.Stdout.Write(bytesConfig); err != nil {
		base.Fatalf("failed to write proto config: %s", err)
	}
}
