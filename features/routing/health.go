package routing

import "time"

// HealthChecker is the interface for health checkers
type HealthChecker interface {
	// StartScheduler starts the check scheduler
	StartScheduler(selector func() ([]string, error))
	// StopScheduler stops the check scheduler
	StopScheduler()
	// Check start the health checking for given tags.
	Check(tags []string) error
}

// OutboundInfo holds information of an outbound
type OutboundInfo struct {
	Tag    string   // Tag of the outbound
	Values []string // Information of the outbound, which can be different between strategies, like health ping RTT
}

// StrategyInfo holds strategy running information, like selected handlers and others
type StrategyInfo struct {
	Settings    []string        // Strategy settings
	ValueTitles []string        // Value titles of OutboundInfo.Values
	Selects     []*OutboundInfo // Selects of the strategy
	Others      []*OutboundInfo // Other outbounds
}

// BalancingOverrideInfo holds balancing overridden information
type BalancingOverrideInfo struct {
	Until   time.Time
	Selects []string
}

// BalancerInfo holds information of a balancer
type BalancerInfo struct {
	Tag      string // Tag of the balancer
	Override *BalancingOverrideInfo
	Strategy *StrategyInfo // Strategy and its running information
}

// RouterChecker represents a router that is able to perform checks for its balancers, and get statistics.
type RouterChecker interface {
	// CheckHanlders performs a health check for specified outbound hanlders.
	CheckHanlders(tags []string) error
	// CheckBalancers performs health checks for specified balancers,
	// if not specified, check them all.
	CheckBalancers(tags []string) error
	// GetBalancersInfo get health info of specific balancer, if balancer not specified, get all
	GetBalancersInfo(tags []string) ([]*BalancerInfo, error)
}
