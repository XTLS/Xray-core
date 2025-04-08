package all

import (
	"fmt"

	"github.com/hosemorinho412/xray-core/common/uuid"
	"github.com/hosemorinho412/xray-core/main/commands/base"
)

var cmdUUID = &base.Command{
	UsageLine: `{{.Exec}} uuid [-i "example"]`,
	Short:     `Generate UUIDv4 or UUIDv5`,
	Long: `
Generate UUIDv4 or UUIDv5.

UUIDv4 (random): {{.Exec}} uuid

UUIDv5 (from input): {{.Exec}} uuid -i "example"
`,
}

func init() {
	cmdUUID.Run = executeUUID // break init loop
}

var input = cmdUUID.Flag.String("i", "", "")

func executeUUID(cmd *base.Command, args []string) {
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
