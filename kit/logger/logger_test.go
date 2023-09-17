//nolint:paralleltest
package logger_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/logger"
)

func Test_Logger_Annotate(t *testing.T) {
	t.Run("Annotate() should init a logger (if missing)", func(t *testing.T) {
		ctx := context.Background()
		ctx = logger.Annotate(ctx, map[string]interface{}{"scan_id": "XVHR3"})

		assertFnOutput(t,
			func() { logger.For(ctx).Info("Initializing scan...") },
			"level=info msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)
	})

	t.Run("Annotate() should inherit context (if present)", func(t *testing.T) {
		ctx := context.Background()
		ctx = logger.Annotate(ctx, map[string]interface{}{"scan_id": "XVHR3"})
		ctx = logger.Annotate(ctx, map[string]interface{}{"user_id": "LLH33"})

		assertFnOutput(t,
			func() { logger.For(ctx).Info("Initializing scan...") },
			"level=info msg=\"Initializing scan...\" scan_id=XVHR3 user_id=LLH33\n",
		)
	})
}

func Test_Logger_SetLevel(t *testing.T) { //nolint: funlen
	ctx := context.Background()
	ctx = logger.Annotate(ctx, map[string]interface{}{"scan_id": "XVHR3"})

	log := logger.For(ctx)

	t.Run("SetLevel(LevelDisabled) shouldn't print any log", func(t *testing.T) {
		log.SetLevel(logger.LevelDisabled)

		assertFnOutput(t,
			func() { log.Debug("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Info("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Warn("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Error("Initializing scan...") },
			"",
		)
	})

	t.Run("SetLevel(LevelDebug) should print all levels", func(t *testing.T) {
		log.SetLevel(logger.LevelDebug)

		assertFnOutput(t,
			func() { log.Debug("Initializing scan...") },
			"level=debug msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Info("Initializing scan...") },
			"level=info msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Warn("Initializing scan...") },
			"level=warn msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Error("Initializing scan...") },
			"level=error msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)
	})

	t.Run("SetLevel(LevelInfo) should print info and above", func(t *testing.T) {
		log.SetLevel(logger.LevelInfo)

		assertFnOutput(t,
			func() { log.Debug("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Info("Initializing scan...") },
			"level=info msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Warn("Initializing scan...") },
			"level=warn msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Error("Initializing scan...") },
			"level=error msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)
	})

	t.Run("SetLevel(LevelWarn) should print warn and above", func(t *testing.T) {
		log.SetLevel(logger.LevelWarn)

		assertFnOutput(t,
			func() { log.Debug("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Info("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Warn("Initializing scan...") },
			"level=warn msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)

		assertFnOutput(t,
			func() { log.Error("Initializing scan...") },
			"level=error msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)
	})

	t.Run("SetLevel(LevelError) should only print errors", func(t *testing.T) {
		log.SetLevel(logger.LevelError)

		assertFnOutput(t,
			func() { log.Debug("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Info("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Warn("Initializing scan...") },
			"",
		)

		assertFnOutput(t,
			func() { log.Error("Initializing scan...") },
			"level=error msg=\"Initializing scan...\" scan_id=XVHR3\n",
		)
	})
}

func Test_Logger_SetWriter(t *testing.T) {
	t.Run("SetWriter(w) should write to w instead of stdout", func(t *testing.T) {
		ctx := context.Background()
		ctx = logger.Annotate(ctx, map[string]interface{}{"scan_id": "XVHR3"})

		r, w, err := os.Pipe()
		require.NoError(t, err)

		log := logger.For(ctx)
		log.SetWriter(w)

		assertFnOutput(t,
			func() { logger.For(ctx).Info("Initializing scan...") },
			"",
		)

		w.Close()

		var buf bytes.Buffer

		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		assert.Contains(t, buf.String(), "level=info msg=\"Initializing scan...\" scan_id=XVHR3\n")
	})
}

func assertFnOutput(t *testing.T, fn func(), exp string) {
	t.Helper()

	stdout := *os.Stdout
	defer func() {
		*os.Stdout = stdout
	}()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	*os.Stdout = *w

	fn()
	time.Sleep(time.Millisecond)
	w.Close()

	var buf bytes.Buffer

	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), exp)
}
