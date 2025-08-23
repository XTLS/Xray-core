package convert

import (
	"fmt"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/cmdarg"
	creflect "github.com/xtls/xray-core/common/reflect"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"

	"google.golang.org/protobuf/proto"
)

var cmdProtobuf = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} convert pb [-outpbfile file] [-debug] [-type] [json file] [json file] ...",
	Short:       "Convert multiple json configs to protobuf",
	Long: `
Convert multiple configs to ProtoBuf. JSON, YAML and TOML can be used.

Arguments:

	-o file, -outpbfile file
		Write the ProtoBuf output (eg. mix.pb) to specified file location.

	-d, -debug
		Show mix.pb as JSON format.
		FOR DEBUGGING ONLY!
		DO NOT PASS THIS OUTPUT TO XRAY-CORE!

	-t, -type
		Inject type information into debug output.

Examples:

    {{.Exec}} convert pb -outpbfile output.pb config.json c1.json c2.json c3.json
    {{.Exec}} convert pb -debug mix.pb
	`,
	Run: executeConvertConfigsToProtobuf,
}

func executeConvertConfigsToProtobuf(cmd *base.Command, args []string) {

	var optFile string
	var optDump bool
	var optType bool

	cmd.Flag.StringVar(&optFile, "o", "", "")
	cmd.Flag.StringVar(&optFile, "outpbfile", "", "")
	cmd.Flag.BoolVar(&optDump, "d", false, "")
	cmd.Flag.BoolVar(&optDump, "debug", false, "")
	cmd.Flag.BoolVar(&optType, "t", false, "")
	cmd.Flag.BoolVar(&optType, "type", false, "")
	cmd.Flag.Parse(args)

	unnamedArgs := cmdarg.Arg{}
	for _, v := range cmd.Flag.Args() {
		unnamedArgs.Set(v)
	}

	if len(optFile) > 0 {
		switch core.GetFormatByExtension(getFileExtension(optFile)){
		case "protobuf", "":
			fmt.Println("Output ProtoBuf file is ", optFile)
		default:
			base.Fatalf("-outpbfile followed by a possible original config.")
		}
	} else if !optDump {
		base.Fatalf("-outpbfile not specified")
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

	if len(optFile) > 0 {
		bytesConfig, err := proto.Marshal(pbConfig)
		if err != nil {
			base.Fatalf("failed to marshal proto config: %s", err)
		}

		f, err := os.Create(optFile)
		if err != nil {
			base.Fatalf("failed to create proto file: %s", err)
		}
		defer f.Close()

		if _, err := f.Write(bytesConfig); err != nil {
			base.Fatalf("failed to write proto file: %s", err)
		}
	}
}

func getFileExtension(filename string) string {
	idx := strings.LastIndexByte(filename, '.')
	if idx == -1 {
		return ""
	}
	return filename[idx+1:]
}
