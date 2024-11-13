package scan

import (
	"context"

	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
)

// NewReqBuilderPool instantiates a pooled (limited) [RequesterBuilder],
// with a maximum of [size] concurrent requesters.
//
// Take a look at [requester_pool_test.go] for usage examples.
func NewReqBuilderPool(ctx context.Context, reqBuilder RequesterBuilder, size uint32) RequesterBuilder {
	// We use `struct{}` as the representation, in order to keep control
	// over the amount of clients that are created.
	//
	// However, we don't reuse instances for now, as the instance type
	// really depends on the request type, and we don't want to mix them.
	pool := make(chan struct{}, size)

	// Fill the pool with the maximum amount of requesters.
	for _, i := range make([]struct{}, int(size)) {
		pool <- i
	}

	return func(req *request.Request) (Requester, error) {
		select {
		// If there are requesters available in the pool, it returns them.
		case <-pool:
			return newRequesterPooled(pool, reqBuilder, req)
		default:
			// Otherwise, we just wait.
			select {
			case <-pool:
				return newRequesterPooled(pool, reqBuilder, req)
			case <-ctx.Done():
				if cause := context.Cause(ctx); cause != nil {
					return nil, cause
				}
				return nil, ctx.Err()
			}
		}
	}
}

var _ Requester = &requesterPooled{}

type requesterPooled struct {
	Requester
	pool chan struct{}
}

func newRequesterPooled(pool chan struct{}, reqBuilder RequesterBuilder, req *request.Request) (*requesterPooled, error) {
	requester, err := reqBuilder(req)
	if err != nil {
		return nil, err
	}

	return &requesterPooled{
		Requester: requester,
		pool:      pool,
	}, nil
}

func (rp *requesterPooled) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	defer func() { rp.pool <- struct{}{} }()
	return rp.Requester.Do(ctx, req)
}
