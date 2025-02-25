package convert

import (
	"encoding/json"
	"fmt"
	"io"

	creflect "github.com/xtls/xray-core/common/reflect"
	cserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/main/confloader"
)

var cmdJson = &base.Command{
	CustomFlags: true,
	UsageLine:   "{{.Exec}} convert json [-type] [stdin:] [typedMessage file] ",
	Short:       "Convert typedMessage to json",
	Long: `
Convert ONE typedMessage to json.

Where typedMessage file need to be in the following format:

{
  "type": "xray.proxy.shadowsocks.Account",
  "value": "CgMxMTEQBg=="
}

Arguments:

	-t, -type
		Inject type infomation.

Examples:

    {{.Exec}} convert json user.tmsg
	`,
	Run: executeTypedMessageToJson,
}

func executeTypedMessageToJson(cmd *base.Command, args []string) {

	var injectTypeInfo bool
	cmd.Flag.BoolVar(&injectTypeInfo, "t", false, "")
	cmd.Flag.BoolVar(&injectTypeInfo, "type", false, "")
	cmd.Flag.Parse(args)

	if cmd.Flag.NArg() < 1 {
		base.Fatalf("empty input list")
	}

	reader, err := confloader.LoadConfig(cmd.Flag.Arg(0))
	if err != nil {
		base.Fatalf("failed to load config: %s", err)
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		base.Fatalf("failed to read config: %s", err)
	}

	tm := cserial.TypedMessage{}
	if err = json.Unmarshal(b, &tm); err != nil {
		base.Fatalf("failed to unmarshal config: %s", err)
	}

	if j, ok := creflect.MarshalToJson(&tm, injectTypeInfo); ok {
		fmt.Println(j)
	} else {
		base.Fatalf("marshal TypedMessage to json failed")
	}
}
