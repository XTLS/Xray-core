package conf_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"
)

type testWithDuration struct {
	Duration conf.Duration
}

func TestDurationJSON(t *testing.T) {
	expected := &testWithDuration{
		Duration: conf.Duration(time.Hour),
	}
	data, err := json.Marshal(expected)
	if err != nil {
		t.Error(err)
		return
	}
	actual := &testWithDuration{}
	err = json.Unmarshal(data, &actual)
	if err != nil {
		t.Error(err)
		return
	}
	if actual.Duration != expected.Duration {
		t.Errorf("expected: %s, actual: %s", time.Duration(expected.Duration), time.Duration(actual.Duration))
	}
}
