package outbound

// muxConcurrency uses the default only when concurrency is not explicitly set.
func muxConcurrency(configured int32) int32 {
	if configured == 0 {
		return 128
	}
	return configured
}
