package antireplay

type GeneralizedReplayFilter interface {
	Interval() int64
	Check(sum []byte) bool
}
