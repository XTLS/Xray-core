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

// PrintDeprecatedFeatureWarning prints a warning for deprecated and going to be removed feature.
// Do not remove this function even there is no reference to it.
func PrintDeprecatedFeatureWarning(feature string, migrateFeature string) {
	if migrateFeature == nil {
		errors.LogWarning(context.Background(), "This feature " + feature + " is deprecated. Please update your config(s) according to release note and documentation before removal.")
	} else {
		errors.LogWarning(context.Background(), "This feature " + feature + " is deprecated and being migrated to " + migrateFeature + ". Please update your config(s) according to release note and documentation before removal.")
	}
}

// PrintRemovedFeatureError prints an error message for removed feature then return an error. And after long enough time the message can also be removed, uses as an indicator.
// Do not remove this function even there is no reference to it.
func PrintRemovedFeatureError(feature string, migrateFeature string) (error) {
	if migrateFeature == nil {
		return errors.New("The feature " + feature + " has been removed. Please update your config(s) according to release note and documentation.")
	} else {
		return errors.New("The feature " + feature + " has been removed and migrated to " + migrateFeature + ". Please update your config(s) according to release note and documentation.")
	}
}
