package task

import (
	"runtime"

	"golang.org/x/sync/errgroup"
)

// ParallelForN runs fn(0..n-1) in parallel across runtime.GOMAXPROCS(0) worker
// goroutines. Indices are partitioned into contiguous chunks so the number of
// spawned goroutines stays bounded regardless of n.
//
// fn must be safe to call concurrently from different goroutines (each call
// receives its own unique index). Output collected by writing to indexed slots
// in a pre-allocated slice is a common safe pattern.
//
// Returns the first non-nil error reported by fn; other workers may still be
// finishing briefly afterwards.
func ParallelForN(n int, fn func(i int) error) error {
	if n <= 0 {
		return nil
	}
	workers := max(runtime.GOMAXPROCS(0), 1)
	workers = min(workers, n)
	chunk := (n + workers - 1) / workers
	var eg errgroup.Group
	for w := range workers {
		start := w * chunk
		end := min(start+chunk, n)
		if start >= end {
			break
		}
		eg.Go(func() error {
			for i := start; i < end; i++ {
				if err := fn(i); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return eg.Wait()
}
