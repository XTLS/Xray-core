package httpupgrade

import (
	"context"

	"github.com/xmplusdev/xray-core/common"
	"github.com/xmplusdev/xray-core/common/errors"
)

//go:generate go run github.com/xmplusdev/xray-core/common/errors/errorgen

const protocolName = "httpupgrade"

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return nil, errors.New("httpupgrade is a transport protocol.")
	}))
}
