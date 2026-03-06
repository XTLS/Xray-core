package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
)

func TestXrayConfigRejectsBothObservatories(t *testing.T) {
	t.Parallel()

	raw := `{
		"observatory": {
			"subjectSelector": ["a"]
		},
		"burstObservatory": {
			"subjectSelector": ["a"],
			"pingConfig": {
				"destination": "https://connectivitycheck.gstatic.com/generate_204"
			}
		}
	}`

	config := new(Config)
	if err := json.Unmarshal([]byte(raw), config); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	_, err := config.Build()
	if err == nil {
		t.Fatal("Build() error = nil, want conflict error")
	}
	if !strings.Contains(err.Error(), "configure only one of observatory or burstObservatory") {
		t.Fatalf("unexpected error: %v", err)
	}
}
