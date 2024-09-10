package features

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

// Feature is the interface for Xray features. All features must implement this interface.
// All existing features have an implementation in app directory. These features can be replaced by third-party ones.
type Feature interface {
	common.HasType
	common.Runnable
}

// PrintDeprecatedFeatureWarning prints a warning for deprecated feature.
func PrintDeprecatedFeatureWarning(feature string) {
	errors.LogWarning(context.Background(), "You are using a deprecated feature: " + feature + ". Please update your config file(s) with latest configuration format, or update your client software.")
}

// PrintRemovedFeatureError prints an error message for removed feature. And after long enough time the message can also be removed, use as an indicator.
func PrintRemovedFeatureError(feature string) {
	errors.New("The feature " + feature + " is removed. Please update your config file(s) according to release notes and documentations.")
}
