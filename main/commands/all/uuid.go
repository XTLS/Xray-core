package all

import (
	"fmt"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdUUID = &base.Command{
	CustomFlags: true,
	UsageLine:   `{{.Exec}} uuid [-i "example"]`,
	Short:       `Generate UUIDv4 or UUIDv5 (VLESS)`,
	Long: `
Generate UUIDv4 or UUIDv5 (VLESS).

Arguments:

	-i
		Generate uuid from input (UUIDv5).

Example:

	UUIDv4 (random): {{.Exec}} {{.LongName}}
	UUIDv5 (from input): {{.Exec}} {{.LongName}} -i example
`,
	Run: executeUUID,
}

func executeUUID(cmd *base.Command, args []string) {
	var input = cmd.Flag.String("i", "", "")
	cmd.Flag.Parse(args)
	var output string
	if l := len(*input); l == 0 {
		u := uuid.New()
		output = u.String()
	} else if l <= 30 {
		u, _ := uuid.ParseString(*input)
		output = u.String()
	} else {
		output = "Input must be within 30 bytes."
	}
	fmt.Println(output)
}
