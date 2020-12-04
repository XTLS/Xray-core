package json

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"io"
	"os"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cmdarg"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/confloader"
)

func init() {
	common.Must(core.RegisterConfigLoader(&core.ConfigFormat{
		Name:      "JSON",
		Extension: []string{"json"},
		Loader: func(input interface{}) (*core.Config, error) {
			switch v := input.(type) {
			case cmdarg.Arg:
				r, err := confloader.LoadExtConfig(v, os.Stdin)
				if err != nil {
					return nil, newError("failed to execute xctl to convert config file.").Base(err).AtWarning()
				}
				return core.LoadConfig("protobuf", "", r)
			case io.Reader:
				r, err := confloader.LoadExtConfig([]string{"stdin:"}, os.Stdin)
				if err != nil {
					return nil, newError("failed to execute xctl to convert config file.").Base(err).AtWarning()
				}
				return core.LoadConfig("protobuf", "", r)
			default:
				return nil, newError("unknown type")
			}
		},
	}))
}
