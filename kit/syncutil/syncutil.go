package syncutil

import (
	"sync"
	"time"
)

// WaitGroup defines the behavior of a `Wait`-able object.
type WaitGroup interface {
	Wait()
}

// WaitOrForget waits for the given [WaitGroup] to be done or forgets about it after a given duration.
// Similar to the concept of "fire & forget", but waiting for some time before forgetting, and returning
// whether the `WaitGroup` is done or not within the duration time.
func WaitOrForget(wg WaitGroup, duration ...time.Duration) bool {
	const defaultDuration = 10 * time.Millisecond
	waitFor := defaultDuration
	if len(duration) > 0 {
		waitFor = duration[0]
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		return true
	case <-time.After(waitFor):
		return false
	}
}

// WaitGroupWithCount defines the behavior of a [WaitGroup] with a count.
type WaitGroupWithCount struct {
	count int
	mu    *sync.Mutex
	wg    *sync.WaitGroup
}

// NewWaitGroupWithCount constructs a new instance of [WaitGroupWithCount].
func NewWaitGroupWithCount() *WaitGroupWithCount {
	return &WaitGroupWithCount{
		count: 0,
		mu:    &sync.Mutex{},
		wg:    &sync.WaitGroup{},
	}
}

// Add adds the given delta to the count of the [WaitGroupWithCount].
// Equivalent to [sync.WaitGroup.Add], but for [WaitGroupWithCount].
func (w *WaitGroupWithCount) Add(delta int) {
	if delta < 1 {
		panic("syncutil: negative WaitGroupWithCount.Add delta")
	}

	w.mu.Lock()
	w.wg.Add(delta)
	w.count += delta
	w.mu.Unlock()
}

// Done decrements the count of the [WaitGroupWithCount].
// Equivalent to [sync.WaitGroup.Done], but for [WaitGroupWithCount].
func (w *WaitGroupWithCount) Done() {
	w.mu.Lock()
	w.wg.Done()
	w.count--
	w.mu.Unlock()
}

// Wait blocks until the count of the [WaitGroupWithCount] is zero.
// Equivalent to [sync.WaitGroup.Wait], but for [WaitGroupWithCount].
func (w *WaitGroupWithCount) Wait() {
	w.wg.Wait()
}

// Count returns the count of [WaitGroupWithCount].
func (w *WaitGroupWithCount) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}
