package all

import (
	"fmt"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdUUID = &base.Command{
	UsageLine: "{{.Exec}} uuid",
	Short:     "Generate new UUIDs",
	Long: `
Generate new UUIDs.
	`,
	Run: executeUUID,
}

func executeUUID(cmd *base.Command, args []string) {
	u := uuid.New()
	fmt.Println(u.String())
}
