package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/go-logfmt/logfmt"
)

const (
	logEntryKey     = "gbounty-log-entry-key"
	logLineMsgKey   = "msg"
	logLineLevelKey = "level"
	logLineTimeKey  = "time"
)

// Logging levels used by the Logger. These define the severity of log messages.
const (
	// LevelDisabled disables all logging.
	LevelDisabled Level = "disabled"

	// LevelDebug is used for detailed debug information.
	LevelDebug Level = "debug"

	// LevelInfo is used for informational messages.
	LevelInfo Level = "info"

	// LevelWarn is used for warning messages that indicate a potential issue.
	LevelWarn Level = "warn"

	// LevelError is used for error messages that indicate a failure.
	LevelError Level = "error"
)

// Level defines the severity level for log messages.
// It determines which log messages should be output based on the Logger's configured level.
type Level string

func (l Level) shouldLog(other Level) bool {
	switch l {
	case LevelDisabled:
		// Nothing
		return false
	case LevelDebug:
		// Everything
		return true
	case LevelInfo:
		// Everything except debug
		return other != LevelDebug
	case LevelWarn:
		// Only warn and error
		return other == LevelWarn || other == LevelError
	case LevelError:
		// Only error
		return other == LevelError
	}

	// Unknown log level?
	return false
}

type entryKey string

// Logger provides a context-aware logging mechanism with
// support for various log levels and custom key-value annotations.
type Logger struct {
	sync.RWMutex
	Level
	w  io.Writer
	k  []string
	kv map[string]interface{}
}

// Annotate adds key-value pairs to the Logger associated with the given context.
// The key-value pairs are stored in the Logger and used in subsequent log entries.
// Returns a new context with the updated Logger.
func Annotate(ctx context.Context, kv map[string]interface{}) context.Context {
	logger := For(ctx)

	logger.Lock()
	defer logger.Unlock()

	for k, v := range kv {
		logger.kv[k] = v
		logger.k = append(logger.k, k)
	}

	return context.WithValue(ctx, entryKey(logEntryKey), logger)
}

// For retrieves the Logger from the context. If no Logger is found, a new default Logger is returned.
func For(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(entryKey(logEntryKey)).(*Logger); ok && logger != nil {
		return logger
	}

	return build()
}

func build() *Logger {
	return &Logger{
		w:     os.Stdout,
		kv:    make(map[string]interface{}),
		Level: LevelInfo,
	}
}

// SetLevel sets the logging level for the Logger.
// Logs with a lower priority than the set level will not be logged.
func (l *Logger) SetLevel(level Level) {
	l.Lock()
	l.Level = level
	l.Unlock()
}

// SetWriter sets the output destination for the Logger's log entries.
func (l *Logger) SetWriter(w io.Writer) {
	l.Lock()
	l.w = w
	l.Unlock()
}

// Debug logs a message at the Debug level.
// This level is used for detailed debug information.
func (l *Logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

// Debugf logs a formatted message at the Debug level.
func (l *Logger) Debugf(msg string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(msg, args...))
}

// Info logs a message at the Info level.
// This level is used for informational messages.
func (l *Logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

// Infof logs a formatted message at the Info level.
func (l *Logger) Infof(msg string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(msg, args...))
}

// Warn logs a message at the Warn level.
// This level is used for warning messages that indicate a potential issue.
func (l *Logger) Warn(msg string) {
	l.log(LevelWarn, msg)
}

// Warnf logs a formatted message at the Warn level.
func (l *Logger) Warnf(msg string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(msg, args...))
}

// Error logs a message at the Error level.
// This level is used for error messages that indicate a failure.
func (l *Logger) Error(msg string) {
	l.log(LevelError, msg)
}

// Errorf logs a formatted message at the Error level.
func (l *Logger) Errorf(msg string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(msg, args...))
}

func (l *Logger) log(level Level, msg string) {
	nowInNano := time.Now().UnixNano()

	go func() {
		if !l.shouldLog(level) {
			return
		}

		fmtMsg, fmtErr := l.fmt(level, nowInNano, msg)

		var err error

		if fmtErr == nil {
			_, err = fmt.Fprintf(l.w, fmt.Sprintf("%s\n", string(fmtMsg))) //nolint
		} else {
			_, err = fmt.Fprintf(l.w, buildErrLogFmtLine("Cannot build fmt log", msg, err)) //nolint
		}

		if err != nil {
			fmt.Printf(buildErrLogFmtLine("Cannot write to log output", msg, err)) //nolint
		}
	}()
}

func (l *Logger) shouldLog(level Level) bool {
	l.RLock()
	defer l.RUnlock()
	return l.Level.shouldLog(level)
}

func buildErrLogFmtLine(msg, origMsg string, err error) string {
	return fmt.Sprintf("%s=error %s=\"%s\" error=\"%s\" original_msg=\"%s\"\n", logLineLevelKey, logLineMsgKey, msg, err.Error(), origMsg)
}

func (l *Logger) fmt(level Level, now int64, msg string) ([]byte, error) {
	l.RLock()
	defer l.RUnlock()

	const defaultKVLen = 6
	kvLogMeta := make([]interface{}, 0, len(l.kv)+defaultKVLen)
	kvLogMeta = append(kvLogMeta, logLineTimeKey, now)
	kvLogMeta = append(kvLogMeta, logLineLevelKey, level)
	kvLogMeta = append(kvLogMeta, logLineMsgKey, msg)

	for _, k := range l.k {
		kvLogMeta = append(kvLogMeta, k, l.kv[k])
	}

	return logfmt.MarshalKeyvals(kvLogMeta...)
}
