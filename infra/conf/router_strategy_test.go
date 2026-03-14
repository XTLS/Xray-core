package conf

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
)

func TestStrategyLeastLoadConfigBuildSetsNewSmoothingFields(t *testing.T) {
	config, err := (&strategyLeastLoadConfig{
		Expected:      2,
		MaxRTT:        duration.Duration(2 * time.Second),
		Tolerance:     1.5,
		MinSamples:    -1,
		SoftFailGrace: 3,
	}).Build()
	if err != nil {
		t.Fatal("expected leastload config to build:", err)
	}

	result := config.(*router.StrategyLeastLoadConfig)
	if result.GetMinSamples() != 0 {
		t.Fatalf("expected negative minSamples to clamp to 0, got %d", result.GetMinSamples())
	}
	if result.GetSoftFailGrace() != 3 {
		t.Fatalf("expected softFailGrace to be preserved, got %d", result.GetSoftFailGrace())
	}
	if result.GetTolerance() != 1 {
		t.Fatalf("expected tolerance to clamp to 1, got %f", result.GetTolerance())
	}
	if result.GetMaxRTT() != int64(2*time.Second) {
		t.Fatalf("expected maxRTT to be preserved, got %d", result.GetMaxRTT())
	}
}
