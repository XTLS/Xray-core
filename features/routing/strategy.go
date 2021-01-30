package routing

import "time"

// BalancingStrategy is the interface for balancing strategies
type BalancingStrategy interface {
	// Pick pick one outbound from candidates. Unlike the SelectAndPick(),
	// it skips the select procedure (select all & pick one).
	Pick(candidates []string) string
	// SelectAndPick selects qualified nodes from candidates then pick one.
	SelectAndPick(candidates []string) string
	// GetInformation gets information of the strategy
	GetInformation(tags []string) *StrategyInfo
}

// BalancingOverrider is the interface of those who can override
// the selecting of its balancers
type BalancingOverrider interface {
	// OverrideSelecting overrides the selects of specified balancer, for 'validity'
	// duration of time.
	OverrideSelecting(balancer string, selects []string, validity time.Duration) error
}
