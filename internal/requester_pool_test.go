package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	scan "github.com/bountysecurity/gbounty/internal"
	internalhttp "github.com/bountysecurity/gbounty/internal/platform/http"
	"github.com/bountysecurity/gbounty/internal/platform/http/client"
	"github.com/bountysecurity/gbounty/internal/platform/http/stdclient"
	"github.com/bountysecurity/gbounty/internal/request"
)

func TestPool(t *testing.T) {
	t.Parallel()

	getRequester := scan.NewReqBuilderPool(
		context.Background(),
		func(*request.Request) (scan.Requester, error) {
			return client.New(), nil
		},
		2,
	)

	req1, err1 := getRequester(&request.Request{})
	require.NotNil(t, req1)
	require.NoError(t, err1)

	req2, err2 := getRequester(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)
}

func TestPool_ExistingIsLimitedBySize(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(context.Background())
	getRequester := scan.NewReqBuilderPool(
		ctx,
		func(*request.Request) (scan.Requester, error) {
			return client.New(), nil
		},
		2,
	)

	req1, err1 := getRequester(&request.Request{})
	require.NotNil(t, req1)
	require.NoError(t, err1)

	req2, err2 := getRequester(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)

	var (
		req3 scan.Requester
		err3 error
		sync = make(chan struct{}, 1)
	)
	go func() {
		sync <- struct{}{}
		req3, err3 = getRequester(&request.Request{})
		sync <- struct{}{}
	}()

	<-sync
	cause := errors.New("paused") //nolint:goerr113
	cancel(cause)
	<-sync

	require.Nil(t, req3)
	require.ErrorIs(t, err3, cause)
}

func TestPool_IsFilledBack(t *testing.T) {
	t.Parallel()

	getRequester := scan.NewReqBuilderPool(
		context.Background(),
		func(*request.Request) (scan.Requester, error) {
			return client.New(), nil
		},
		1,
	)

	req1, err1 := getRequester(&request.Request{})
	require.NotNil(t, req1)
	require.NoError(t, err1)

	sync := make(chan struct{}, 1)

	go func() {
		sync <- struct{}{}
		_, _ = req1.Do(context.Background(), &request.Request{})
		sync <- struct{}{}
	}()

	<-sync
	<-sync

	req2, err2 := getRequester(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)
}

func TestPool_Complete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const maxClients = 5

	basePool := internalhttp.NewClientPool(
		ctx,
		func() scan.Requester { return client.New() },
		maxClients,
	)

	stdPool := internalhttp.NewClientPool(
		ctx,
		func() scan.Requester { return stdclient.New() },
		maxClients,
	)

	reqBuilder := scan.NewReqBuilderPool(
		ctx,
		func(r *request.Request) (scan.Requester, error) {
			// If it looks like an HTTP/2 request:
			if strings.Contains(r.Proto, "HTTP/2") {
				return stdPool(r)
			}
			// Otherwise, we use our own client.
			return basePool(r)
		},
		maxClients,
	)

	baseReq, err := reqBuilder(&request.Request{Proto: "HTTP/1.1"})
	require.NotNil(t, baseReq)
	require.NoError(t, err)

	stdReq, err := reqBuilder(&request.Request{Proto: "HTTP/2"})
	require.NotNil(t, stdReq)
	require.NoError(t, err)

	sync := make(chan struct{}, 1)

	go func() {
		sync <- struct{}{}
		_, _ = baseReq.Do(context.Background(), &request.Request{})
		sync <- struct{}{}
		_, _ = stdReq.Do(context.Background(), &request.Request{})
		sync <- struct{}{}
	}()

	<-sync
	<-sync
	<-sync

	baseReq2, err := reqBuilder(&request.Request{Proto: "HTTP/1.1"})
	require.NotNil(t, baseReq2)
	require.NoError(t, err)

	stdReq2, err := reqBuilder(&request.Request{Proto: "HTTP/2"})
	require.NotNil(t, stdReq2)
	require.NoError(t, err)
}
