package routing

type BalancerSelector interface {
	PickBalancerOutbound(tag string) (string, bool, error)
}

type BalancerOverrider interface {
	SetOverrideTarget(tag, target string) error
	GetOverrideTarget(tag string) (string, error)
}

type BalancerPrincipleTarget interface {
	GetPrincipleTarget(tag string) ([]string, error)
}
