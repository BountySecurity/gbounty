package pool

import (
	"context"
	"sync"
)

// Pool is an abstraction of a pool of workers. That means, a set of goroutines that do some work.
type Pool struct {
	ch chan func()
	wg *sync.WaitGroup
}

// New constructs a new instance of a [Pool], ready to use.
func New(ctx context.Context, workers int) Pool {
	ch := make(chan func())
	wg := &sync.WaitGroup{}

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				// On each step, we first check if the context is done.
				// Otherwise, we could read from channel for some times,
				// even if the context is already done, cause the select
				// statement cases have no order.
				select {
				case <-ctx.Done():
					return
				default:
				}

				// After the initial check, we still need to check what
				// happens first: either the context is done or a new
				// function is received from the channel.
				// Otherwise, this operation might be blocking
				// forever, preventing a graceful shutdown.
				select {
				case <-ctx.Done():
					return
				case fn, ok := <-ch:
					if !ok {
						return
					}
					fn()
				}
			}
		}()
	}

	return Pool{ch: ch, wg: wg}
}

// Run pushes some work function (a `func()`) to the pool.
func (p Pool) Run(ctx context.Context, fn func()) {
	select {
	case p.ch <- fn:
	case <-ctx.Done():
	}
}

// BareRun is similar to [Run] but it also accepts a function that will be
// executed  when the given work function cannot be handled by the pool workers.
func (p Pool) BareRun(ctx context.Context, fn func(), nop func()) {
	select {
	case p.ch <- fn:
	case <-ctx.Done():
		nop()
	}
}

// Close closes the [Pool].
// It is blocking, and it waits until all th work is done.
func (p Pool) Close() {
	close(p.ch)
	p.wg.Wait()
}
