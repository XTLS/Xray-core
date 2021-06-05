package conf

import (
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
	// health check settings
	HealthCheck *healthCheckSettings `json:"healthCheck,omitempty"`
	// weight settings
	Costs []*router.StrategyWeight `json:"costs,omitempty"`
	// ping rtt baselines
	Baselines []Duration `json:"baselines,omitempty"`
	// expected nodes count to select
	Expected int32 `json:"expected,omitempty"`
	// max acceptable rtt, filter away high delay nodes. defalut 0
	MaxRTT Duration `json:"maxRTT,omitempty"`
	// acceptable failure rate
	Tolerance float64 `json:"tolerance,omitempty"`
}

// healthCheckSettings holds settings for health Checker
type healthCheckSettings struct {
	Destination   string   `json:"destination"`
	Connectivity  string   `json:"connectivity"`
	Interval      Duration `json:"interval"`
	SamplingCount int      `json:"sampling"`
	Timeout       Duration `json:"timeout"`
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
			Interval:      int64(v.HealthCheck.Interval),
			Timeout:       int64(v.HealthCheck.Timeout),
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
	config.MaxRTT = int64(v.MaxRTT)
	if config.MaxRTT < 0 {
		config.MaxRTT = 0
	}
	config.Baselines = make([]int64, 0)
	for _, b := range v.Baselines {
		if b <= 0 {
			continue
		}
		config.Baselines = append(config.Baselines, int64(b))
	}
	return config, nil
}
