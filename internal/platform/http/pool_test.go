package http_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/platform/http"
	"github.com/bountysecurity/gbounty/internal/platform/http/client"
	"github.com/bountysecurity/gbounty/internal/request"
)

func TestPool(t *testing.T) {
	t.Parallel()

	getClient := http.NewClientPool(
		context.Background(),
		func() scan.Requester {
			return client.New()
		},
		2,
	)

	req1, err1 := getClient(&request.Request{})
	require.NotNil(t, req1)
	require.NoError(t, err1)

	req2, err2 := getClient(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)
}

func TestPool_ExistingIsLimitedBySize(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(context.Background())
	getClient := http.NewClientPool(
		ctx,
		func() scan.Requester {
			return client.New()
		},
		2,
	)

	req1, err1 := getClient(&request.Request{})
	require.NotNil(t, req1)
	require.NoError(t, err1)

	req2, err2 := getClient(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)

	var (
		req3 scan.Requester
		err3 error
		sync = make(chan struct{}, 1)
	)
	go func() {
		sync <- struct{}{}
		req3, err3 = getClient(&request.Request{})
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

	getClient := http.NewClientPool(
		context.Background(),
		func() scan.Requester {
			return client.New()
		},
		1,
	)

	req1, err1 := getClient(&request.Request{})
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

	req2, err2 := getClient(&request.Request{})
	require.NotNil(t, req2)
	require.NoError(t, err2)

	assert.Same(t, req1, req2)
}
