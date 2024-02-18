package burst

import (
	"math"
	"time"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

const (
	rttFailed = time.Duration(math.MaxInt64 - iota)
	rttUntested
	rttUnqualified
)
