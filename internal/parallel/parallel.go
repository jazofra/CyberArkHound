// Package parallel runs a function over a slice with a bounded number of
// goroutines.
package parallel

import (
	"context"
	"sync"
	"sync/atomic"
)

// ForEach calls fn once for every item using at most workers goroutines.
//
// Only workers goroutines are ever started, however many items there are, so
// fanning out over hundreds of thousands of accounts does not first allocate a
// goroutine per account. Once ctx is done no further items are handed out;
// calls already in progress run to completion. ForEach returns when every
// started call has returned.
func ForEach[T any](ctx context.Context, items []T, workers int, fn func(idx int, item T)) {
	if len(items) == 0 {
		return
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				idx := int(next.Add(1) - 1)
				if idx >= len(items) {
					return
				}
				fn(idx, items[idx])
			}
		}()
	}
	wg.Wait()
}
