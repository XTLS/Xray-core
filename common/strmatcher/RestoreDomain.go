package strmatcher

// RestoreDomainType of domain value.
type RestoreDomainType int32

const (
	// RestoreDomainTypePlain The value is used as is.
	RestoreDomainTypePlain RestoreDomainType = 0
	// RestoreDomainTypeRegex The value is used as a regular expression.
	RestoreDomainTypeRegex RestoreDomainType = 1
	// RestoreDomainTypeDomain The value is a root domain.
	RestoreDomainTypeDomain RestoreDomainType = 2
	// RestoreDomainTypeFull The value is a domain.
	RestoreDomainTypeFull RestoreDomainType = 3
)
