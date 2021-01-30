package conf

import (
	"time"

	"google.golang.org/protobuf/proto"
	"github.com/xtls/xray-core/app/router"
)

const (
	strategyRandom     string = "random"
	strategyLeastPing  string = "leastping"
	strategyRoundRobin string = "roundrobin"
	strategyLeastLoad  string = "leastload"
)

var (
	strategyConfigLoader = NewJSONConfigLoader(ConfigCreatorCache{
		strategyRandom:    func() interface{} { return new(strategyEmptyConfig) },
		strategyLeastLoad: func() interface{} { return new(strategyLeastLoadConfig) },
	}, "type", "settings")
)

type strategyEmptyConfig struct {
}

func (v *strategyEmptyConfig) Build() (proto.Message, error) {
	return nil, nil
}

type strategyLeastLoadConfig struct {
	// note the time values of the HealthCheck holds is not
	// 'time.Duration' but plain number, sice they were parsed
	// directly from json
	HealthCheck *router.HealthPingSettings `json:"healthCheck,omitempty"`
	// weight settings
	Costs []*router.StrategyWeight `json:"costs,omitempty"`
	// ping rtt baselines (ms)
	Baselines []int `json:"baselines,omitempty"`
	// expected nodes count to select
	Expected int32 `json:"expected,omitempty"`
	// max acceptable rtt (ms), filter away high delay nodes. defalut 0
	MaxRTT int `json:"maxRTT,omitempty"`
	// acceptable failure rate
	Tolerance float64 `json:"tolerance,omitempty"`
}

// Build implements Buildable.
func (v *strategyLeastLoadConfig) Build() (proto.Message, error) {
	config := &router.StrategyLeastLoadConfig{
		HealthCheck: &router.HealthPingConfig{},
	}
	if v.HealthCheck != nil {
		config.HealthCheck = &router.HealthPingConfig{
			Destination:   v.HealthCheck.Destination,
			Connectivity:  v.HealthCheck.Connectivity,
			Interval:      int64(v.HealthCheck.Interval * time.Second),
			Timeout:       int64(v.HealthCheck.Timeout * time.Second),
			SamplingCount: int32(v.HealthCheck.SamplingCount),
		}
	}
	config.Costs = v.Costs
	config.Tolerance = float32(v.Tolerance)
	if config.Tolerance < 0 {
		config.Tolerance = 0
	}
	if config.Tolerance > 1 {
		config.Tolerance = 1
	}
	config.Expected = v.Expected
	if config.Expected < 0 {
		config.Expected = 0
	}
	config.MaxRTT = int64(time.Duration(v.MaxRTT) * time.Millisecond)
	if config.MaxRTT < 0 {
		config.MaxRTT = 0
	}
	config.Baselines = make([]int64, 0)
	for _, b := range v.Baselines {
		if b <= 0 {
			continue
		}
		config.Baselines = append(config.Baselines, int64(time.Duration(b)*time.Millisecond))
	}
	return config, nil
}
