package panics

import (
	"context"
	"runtime/debug"

	"github.com/bountysecurity/gbounty/kit/logger"
)

// Log logs a panic to the logger, including the stack trace.
func Log(ctx context.Context) {
	if r := recover(); r != nil {
		logger.For(ctx).Errorf("Fatal error (panic): %v", r)
		logger.For(ctx).Errorf("Stack trace: %s", string(debug.Stack()))
	}
}
