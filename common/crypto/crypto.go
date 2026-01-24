// Package crypto provides common crypto libraries for Xray.
package crypto // import "github.com/xtls/xray-core/common/crypto"

import (
	"crypto/rand"
	"math/big"
	"time"
)

func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}

func RandDuration(from int64, to int64, unit time.Duration) time.Duration {
	return time.Duration(RandBetween(from, to)) * unit
}
