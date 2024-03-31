package panics_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/logger"
	"github.com/bountysecurity/gbounty/kit/panics"
)

func TestLog(t *testing.T) {
	t.Parallel()

	// We prepare a test context with a logger, and we get it.
	ctx := logger.Annotate(context.Background(), map[string]interface{}{"test": "test"})
	log := logger.For(ctx)

	// We set the writer, to capture what's logged.
	buff := bytes.NewBuffer(make([]byte, 0, 20000))
	log.SetWriter(buff)

	// We defer the check of the log output, because it should happen
	// once the panic has been captured.
	defer func() {
		// The log operation is asynchronous, so we wait a bit.
		time.Sleep(100 * time.Millisecond)
		assert.Contains(t, buff.String(), `level=error msg="Fatal error (panic): error" test=test`)
		assert.Contains(t, buff.String(), `level=error msg="Stack trace:`)
		assert.Contains(t, buff.String(), `github.com/bountysecurity/gbounty/kit/panics.Log`)
	}()

	defer panics.Log(ctx)
	panic("error")
	require.Fail(t, "should not reach here") //nolint:govet
}
