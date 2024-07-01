package features

import (
	"context"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
)

//go:generate go run github.com/GFW-knocker/Xray-core/common/errors/errorgen

// Feature is the interface for Xray features. All features must implement this interface.
// All existing features have an implementation in app directory. These features can be replaced by third-party ones.
type Feature interface {
	common.HasType
	common.Runnable
}

// PrintDeprecatedFeatureWarning prints a warning for deprecated feature.
func PrintDeprecatedFeatureWarning(feature string) {
	errors.LogInfo(context.Background(), "You are using a deprecated feature: "+feature+". Please update your config file with latest configuration format, or update your client software.")
}
