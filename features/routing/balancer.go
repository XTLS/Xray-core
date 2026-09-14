package routing

// BalancerPicker selects an outbound using a named balancer without evaluating
// routing rules. Selection happens on each call, not for each reused connection.
type BalancerPicker interface {
	PickOutbound(tag string) (string, error)
}

type BalancerOverrider interface {
	SetOverrideTarget(tag, target string) error
	GetOverrideTarget(tag string) (string, error)
}

type BalancerPrincipleTarget interface {
	GetPrincipleTarget(tag string) ([]string, error)
}
