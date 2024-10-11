package errors

import (
	"context"
)

// PrintMigrateFeatureInfo prints a notice of the upcoming feature migration.
// Place it after the source feature related config file pharser code.
// Important note: Only use this when the target migrating feature is under construction.
// Important note: Even when the target migrating feature has finished its construction, this notice can still be used yet before announcing deprecation of the old feature.
// Do not remove this function even there is no reference to it.
func PrintMigrateFeatureInfo(sourceFeature string, targetFeature string) {
	LogInfo(context.Background(), "The feature "+sourceFeature+" will be migrated to "+targetFeature+" in the future.")
}

// PrintDeprecatedFeatureWarning prints a warning for deprecated and going to be removed feature.
// Do not remove this function even there is no reference to it.
func PrintDeprecatedFeatureWarning(feature string, migrateFeature string) {
	if len(migrateFeature) > 0 {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated and being migrated to "+migrateFeature+". Please update your config(s) according to release note and documentation before removal.")
	} else {
		LogWarning(context.Background(), "This feature "+feature+" is deprecated. Please update your config(s) according to release note and documentation before removal.")
	}
}

// PrintRemovedFeatureError prints an error message for removed feature then return an error. And after long enough time the message can also be removed, uses as an indicator.
// Do not remove this function even there is no reference to it.
func PrintRemovedFeatureError(feature string, migrateFeature string) error {
	if len(migrateFeature) > 0 {
		return New("The feature " + feature + " has been removed and migrated to " + migrateFeature + ". Please update your config(s) according to release note and documentation.")
	} else {
		return New("The feature " + feature + " has been removed. Please update your config(s) according to release note and documentation.")
	}
}
