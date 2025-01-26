package http

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

type ClientConstructor func() gbounty.Requester

// NewClientPool instantiates a pooled (limited) Client constructor,
// with a maximum of [size] concurrent requesters.
//
// Take a look at [pool_test.go] for usage examples.
func NewClientPool(ctx context.Context, cc ClientConstructor, size uint32) gbounty.RequesterBuilder {
	var (
		pool     = make(chan gbounty.Requester, size)
		existing atomic.Uint32
		mu       sync.Mutex
	)

	return func(req *request.Request) (gbounty.Requester, error) {
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

var _ gbounty.Requester = &requesterPooled{}

type requesterPooled struct {
	gbounty.Requester
	pool chan gbounty.Requester
}

func (rp *requesterPooled) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	defer func() { rp.pool <- rp }()
	return rp.Requester.Do(ctx, req)
}
