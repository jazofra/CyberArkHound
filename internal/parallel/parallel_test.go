package parallel

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestForEachVisitsEveryItemOnce(t *testing.T) {
	items := make([]int, 1000)
	for i := range items {
		items[i] = i
	}
	var mu sync.Mutex
	seen := make(map[int]int)
	ForEach(context.Background(), items, 7, func(idx, item int) {
		if idx != item {
			t.Errorf("idx %d delivered item %d", idx, item)
		}
		mu.Lock()
		seen[item]++
		mu.Unlock()
	})
	if len(seen) != len(items) {
		t.Fatalf("visited %d items, want %d", len(seen), len(items))
	}
	for item, n := range seen {
		if n != 1 {
			t.Fatalf("item %d visited %d times", item, n)
		}
	}
}

func TestForEachBoundsConcurrency(t *testing.T) {
	const workers = 3
	var running, peak atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 100)
	done := make(chan struct{})
	go func() {
		ForEach(context.Background(), make([]int, 20), workers, func(int, int) {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			started <- struct{}{}
			<-release
			running.Add(-1)
		})
		close(done)
	}()
	for i := 0; i < workers; i++ {
		<-started
	}
	close(release)
	<-done
	if got := peak.Load(); got != workers {
		t.Fatalf("peak concurrency = %d, want %d", got, workers)
	}
}

func TestForEachStopsHandingOutWorkWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	ForEach(ctx, make([]int, 100), 1, func(int, int) {
		if calls.Add(1) == 5 {
			cancel()
		}
	})
	if got := calls.Load(); got != 5 {
		t.Fatalf("calls = %d, want 5 (no new work after cancel)", got)
	}
}

func TestForEachHandlesEmptyAndNonPositiveWorkers(t *testing.T) {
	ForEach(context.Background(), []int(nil), 4, func(int, int) { t.Fatal("called for empty slice") })
	var calls atomic.Int32
	ForEach(context.Background(), []int{1, 2, 3}, 0, func(int, int) { calls.Add(1) })
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}
