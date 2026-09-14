package routing

type BalancerOverrider interface {
	SetOverrideTarget(tag, target string) error
	GetOverrideTarget(tag string) (string, error)
}

type BalancerPrincipleTarget interface {
	GetPrincipleTarget(tag string) ([]string, error)
}

// BalancerPicker return the outbound tag selected by the given balancer
type BalancerPicker interface {
	GetBalancerOutboundTag(balancerTag string) (string, error)
}
