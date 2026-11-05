package protocol

import (
	"math/rand/v2"
	"time"
)

type Timestamp int64

type TimestampGenerator func() Timestamp

func NowTime() Timestamp {
	return Timestamp(time.Now().Unix())
}

func NewTimestampGenerator(base Timestamp, delta int) TimestampGenerator {
	return func() Timestamp {
		rangeInDelta := rand.N(delta*2) - delta
		return base + Timestamp(rangeInDelta)
	}
}
