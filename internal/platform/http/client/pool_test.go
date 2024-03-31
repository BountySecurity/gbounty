package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	
	"github.com/bountysecurity/gbounty/internal/platform/http/client"
)

func TestPool(t *testing.T) {
	t.Parallel()

	getClient := client.NewPool(context.Background(), 2)

	c1, err1 := getClient()
	require.NotNil(t, c1)
	require.NoError(t, err1)

	c2, err2 := getClient()
	require.NotNil(t, c2)
	require.NoError(t, err2)
}

func TestPool_ExistingIsLimitedBySize(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(context.Background())
	getClient := client.NewPool(ctx, 2)

	c1, err1 := getClient()
	require.NotNil(t, c1)
	require.NoError(t, err1)

	c2, err2 := getClient()
	require.NotNil(t, c2)
	require.NoError(t, err2)

	var (
		c3   *client.Pooled
		err3 error
		sync = make(chan struct{}, 1)
	)
	go func() {
		sync <- struct{}{}
		c3, err3 = getClient()
		sync <- struct{}{}
	}()

	<-sync
	cause := errors.New("paused") //nolint:goerr113
	cancel(cause)
	<-sync

	require.Nil(t, c3)
	require.ErrorIs(t, err3, cause)
}
