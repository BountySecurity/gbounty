package http

import (
	"context"
	"sync"
	"sync/atomic"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
)

type ClientConstructor func() scan.Requester

// NewClientPool instantiates a pooled (limited) Client constructor,
// with a maximum of [size] concurrent requesters.
//
// Take a look at [pool_test.go] for usage examples.
func NewClientPool(ctx context.Context, cc ClientConstructor, size uint32) scan.RequesterBuilder {
	var (
		pool     = make(chan scan.Requester, size)
		existing atomic.Uint32
		mu       sync.Mutex
	)

	return func(req *request.Request) (scan.Requester, error) {
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
				return &requesterPooled{
					Requester: cc(),
					pool:      pool,
				}, nil
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

var _ scan.Requester = &requesterPooled{}

type requesterPooled struct {
	scan.Requester
	pool chan scan.Requester
}

func (rp *requesterPooled) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	defer func() { rp.pool <- rp }()
	return rp.Requester.Do(ctx, req)
}
