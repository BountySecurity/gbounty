package stdclient

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
)

// NewPool is a constructor function that creates a new collection of
// [Pooled] clients, on top of a new Client with the given [Opt].
//
// The pool is a buffered channel that can hold up to [size] clients.
// If the pool is full, it will wait until a client is available.
// Use it to limit the number of clients that can be created,
// and thus the total amount of ongoing requests and open connections.
//
// Take a look at [pool_test.go] for usage examples.
func NewPool(ctx context.Context, size uint32, opts ...Opt) func() (*Pooled, error) {
	var (
		pool     = make(chan *Pooled, size)
		existing atomic.Uint32
		mu       sync.Mutex
	)

	return func() (*Pooled, error) {
		mu.Lock()
		defer mu.Unlock()

		select {
		// If there are clients available in the pool, it returns them.
		case client := <-pool:
			return client, nil
		default:
			// If not, it checks whether we reached the maximum amount of clients.
			if existing.Load() < size {
				// If not, we initialize a new client.
				existing.Add(1)
				return NewPooled(pool, opts...), nil
			}
			// Otherwise, we just wait.
			select {
			case client := <-pool:
				return client, nil
			case <-ctx.Done():
				if cause := context.Cause(ctx); cause != nil {
					return nil, cause
				}
				return nil, ctx.Err()
			}
		}
	}
}

type Pooled struct {
	pool chan *Pooled
	*Client
}

func NewPooled(pool chan *Pooled, opts ...Opt) *Pooled {
	return &Pooled{
		pool:   pool,
		Client: New(opts...),
	}
}

func (p *Pooled) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	defer func() { p.pool <- p }()
	return p.Client.Do(ctx, req)
}
